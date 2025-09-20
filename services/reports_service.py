"""Reporting service utilities for analytics views."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlite3 import Connection


@dataclass
class DateRange:
    """Simple container describing an inclusive date span."""

    start: Optional[date]
    end: Optional[date]

    def to_query_bounds(self) -> Tuple[str, str]:
        """Return ISO date strings suitable for SQLite comparisons.

        SQLite stores our dates as TEXT in YYYY-MM-DD format. When no start or
        end is supplied we expand to the natural minimum/maximum supported by
        SQLite so comparisons continue to work without extra SQL branches.
        """

        min_bound = "0001-01-01"
        max_bound = "9999-12-31"
        start_str = self.start.isoformat() if self.start else min_bound
        end_str = self.end.isoformat() if self.end else max_bound
        return start_str, end_str


def coerce_date(value: Optional[str]) -> Optional[date]:
    """Parse an ISO formatted date string safely."""

    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def get_default_range(days: int = 90, *, end: Optional[date] = None) -> DateRange:
    """Return a trailing window ending at ``end`` (defaults to today)."""

    end = end or datetime.now().date()
    start = end - timedelta(days=days - 1)
    return DateRange(start=start, end=end)


def get_client_profitability(
    db: Connection,
    *,
    date_range: DateRange,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Return aggregated invoice totals per client within ``date_range``."""

    start_str, end_str = date_range.to_query_bounds()
    rows = db.execute(
        """
        SELECT
            c.id AS client_id,
            c.name AS client_name,
            COUNT(DISTINCT i.id) AS invoice_count,
            COUNT(DISTINCT i.event_id) AS event_count,
            COALESCE(SUM(i.amount), 0) AS total_invoiced,
            COALESCE(SUM(CASE WHEN i.status = 'paid' THEN i.amount ELSE 0 END), 0) AS paid_total,
            COALESCE(SUM(CASE WHEN i.status != 'paid' THEN i.amount ELSE 0 END), 0) AS outstanding_total,
            MAX(i.issue_date) AS last_invoice_date
        FROM clients c
        JOIN invoices i ON i.client_id = c.id
        WHERE i.issue_date BETWEEN ? AND ?
        GROUP BY c.id, c.name
        HAVING invoice_count > 0
        ORDER BY total_invoiced DESC
        LIMIT ?
        """,
        (start_str, end_str, limit),
    ).fetchall()

    results: List[Dict[str, Any]] = []
    for row in rows:
        total = row["total_invoiced"] or 0
        paid = row["paid_total"] or 0
        outstanding = row["outstanding_total"] or 0
        collection_rate = (paid / total) * 100 if total else 0
        avg_invoice = total / row["invoice_count"] if row["invoice_count"] else 0
        results.append(
            {
                "client_id": row["client_id"],
                "client_name": row["client_name"],
                "invoice_count": row["invoice_count"],
                "event_count": row["event_count"],
                "total_invoiced": round(total, 2),
                "paid_total": round(paid, 2),
                "outstanding_total": round(outstanding, 2),
                "collection_rate": round(collection_rate, 1),
                "avg_invoice": round(avg_invoice, 2),
                "last_invoice_date": row["last_invoice_date"],
            }
        )
    return results


def get_revenue_trend(
    db: Connection,
    *,
    months: int = 6,
    end: Optional[date] = None,
) -> List[Dict[str, Any]]:
    """Return monthly revenue totals for the trailing ``months`` window."""

    end = end or datetime.now().date()
    start = (end.replace(day=1) - timedelta(days=1)).replace(day=1)
    for _ in range(months - 1):
        start = (start.replace(day=1) - timedelta(days=1)).replace(day=1)
    start_str = start.strftime("%Y-%m-01")
    end_str = end.strftime("%Y-%m-%d")

    rows = db.execute(
        """
        SELECT
            strftime('%Y-%m', issue_date) AS period,
            SUM(amount) AS total_amount,
            SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END) AS paid_amount
        FROM invoices
        WHERE issue_date BETWEEN ? AND ?
        GROUP BY period
        ORDER BY period ASC
        """,
        (start_str, end_str),
    ).fetchall()

    trend: List[Dict[str, Any]] = []
    for row in rows:
        trend.append(
            {
                "period": row["period"],
                "total_amount": round(row["total_amount"] or 0, 2),
                "paid_amount": round(row["paid_amount"] or 0, 2),
            }
        )
    return trend


def get_equipment_utilization(
    db: Connection,
    *,
    date_range: DateRange,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Return top equipment usage summaries for the supplied period."""

    start_str, end_str = date_range.to_query_bounds()
    rows = db.execute(
        """
        SELECT
            eq.id AS equipment_id,
            eq.name AS equipment_name,
            eq.quantity AS available_quantity,
            COUNT(DISTINCT ea.event_id) AS event_count,
            COALESCE(SUM(ea.quantity), 0) AS total_quantity,
            MIN(e.event_date) AS first_event_date,
            MAX(e.event_date) AS last_event_date
        FROM equipment eq
        JOIN equipment_assignments ea ON ea.equipment_id = eq.id
        JOIN events e ON e.event_id = ea.event_id
        WHERE e.event_date BETWEEN ? AND ?
        GROUP BY eq.id, eq.name, eq.quantity
        HAVING event_count > 0
        ORDER BY total_quantity DESC, event_count DESC
        LIMIT ?
        """,
        (start_str, end_str, limit),
    ).fetchall()

    results: List[Dict[str, Any]] = []
    for row in rows:
        total_qty = row["total_quantity"] or 0
        events = row["event_count"] or 1
        available = row["available_quantity"] or 0
        avg_per_event = total_qty / events if events else 0
        capacity_ratio = 0
        if available > 0:
            capacity_ratio = min(100, round((avg_per_event / available) * 100, 1))
        results.append(
            {
                "equipment_id": row["equipment_id"],
                "equipment_name": row["equipment_name"],
                "event_count": row["event_count"],
                "total_quantity": total_qty,
                "average_quantity": round(avg_per_event, 2),
                "capacity_ratio": capacity_ratio,
                "available_quantity": available,
                "first_event_date": row["first_event_date"],
                "last_event_date": row["last_event_date"],
            }
        )
    return results


def get_category_mix(
    db: Connection,
    *,
    date_range: DateRange,
) -> List[Dict[str, Any]]:
    """Return event counts per category for the supplied window."""

    start_str, end_str = date_range.to_query_bounds()
    rows = db.execute(
        """
        SELECT
            cat.id AS category_id,
            cat.name AS category_name,
            COUNT(e.event_id) AS event_count
        FROM events e
        LEFT JOIN event_categories cat ON e.category_id = cat.id
        WHERE e.event_date BETWEEN ? AND ?
        GROUP BY cat.id, cat.name
        ORDER BY event_count DESC
        """,
        (start_str, end_str),
    ).fetchall()

    mix: List[Dict[str, Any]] = []
    for row in rows:
        label = row["category_name"] or "Uncategorized"
        mix.append(
            {
                "category_id": row["category_id"],
                "category_name": label,
                "event_count": row["event_count"],
            }
        )
    return mix


def summarize_financials(
    client_rows: Iterable[Dict[str, Any]],
    *,
    total_revenue: float,
    paid_revenue: float,
    outstanding: float,
) -> Dict[str, Any]:
    """Create a quick metrics summary for the header cards."""

    top_client = next(iter(client_rows), None)
    summary = {
        "total_revenue": round(total_revenue, 2),
        "paid_revenue": round(paid_revenue, 2),
        "outstanding": round(outstanding, 2),
        "collection_rate": round((paid_revenue / total_revenue) * 100, 1) if total_revenue else 0,
        "top_client": top_client["client_name"] if top_client else None,
        "top_client_value": top_client["total_invoiced"] if top_client else 0,
    }
    return summary


def compute_financial_totals(db: Connection, *, date_range: DateRange) -> Tuple[float, float, float]:
    """Return (total, paid, outstanding) invoice sums for the range."""

    start_str, end_str = date_range.to_query_bounds()
    row = db.execute(
        """
        SELECT
            COALESCE(SUM(amount), 0) AS total_amount,
            COALESCE(SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END), 0) AS paid_amount,
            COALESCE(SUM(CASE WHEN status != 'paid' THEN amount ELSE 0 END), 0) AS outstanding_amount
        FROM invoices
        WHERE issue_date BETWEEN ? AND ?
        """,
        (start_str, end_str),
    ).fetchone()
    total = row["total_amount"] if row else 0
    paid = row["paid_amount"] if row else 0
    outstanding = row["outstanding_amount"] if row else 0
    return float(total or 0), float(paid or 0), float(outstanding or 0)
