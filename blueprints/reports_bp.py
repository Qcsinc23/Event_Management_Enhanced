from datetime import datetime
from typing import Optional, Tuple

from flask import Blueprint, render_template, request

from helpers import get_db, login_required
from services.reports_service import (
    DateRange,
    coerce_date,
    compute_financial_totals,
    get_category_mix,
    get_client_profitability,
    get_default_range,
    get_equipment_utilization,
    get_revenue_trend,
    summarize_financials,
)

reports_bp = Blueprint('reports', __name__)


def _resolve_date_range(range_key: str, start: Optional[str], end: Optional[str]) -> Tuple[DateRange, str]:
    """Determine the reporting window from query parameters."""

    parsed_start = coerce_date(start)
    parsed_end = coerce_date(end)

    if parsed_start and parsed_end:
        if parsed_start > parsed_end:
            parsed_start, parsed_end = parsed_end, parsed_start
        return DateRange(start=parsed_start, end=parsed_end), 'custom'

    range_key = (range_key or '90').lower()
    today = datetime.now().date()

    if range_key in {'30', '90', '180', '365'}:
        window = int(range_key)
        return get_default_range(window, end=today), range_key

    if range_key == 'ytd':
        start_of_year = today.replace(month=1, day=1)
        return DateRange(start=start_of_year, end=today), 'ytd'

    if range_key == 'all':
        return DateRange(start=None, end=None), 'all'

    # Fallback to 90 days if we don't recognise the input
    return get_default_range(90, end=today), '90'


@reports_bp.route('/reports')
@login_required
def overview():
    range_key = request.args.get('range', '90')
    start = request.args.get('start')
    end = request.args.get('end')

    date_range, active_range = _resolve_date_range(range_key, start, end)

    db = get_db()
    client_rows = get_client_profitability(db, date_range=date_range, limit=15)
    equipment_rows = get_equipment_utilization(db, date_range=date_range, limit=10)
    category_mix = get_category_mix(db, date_range=date_range)

    total_revenue, paid_revenue, outstanding = compute_financial_totals(db, date_range=date_range)
    summary = summarize_financials(
        client_rows,
        total_revenue=total_revenue,
        paid_revenue=paid_revenue,
        outstanding=outstanding,
    )

    revenue_trend = get_revenue_trend(db, months=8, end=date_range.end)

    context = {
        'date_range': date_range,
        'active_range': active_range,
        'summary': summary,
        'client_rows': client_rows,
        'equipment_rows': equipment_rows,
        'category_mix': category_mix,
        'revenue_trend': revenue_trend,
        'has_data': bool(client_rows or equipment_rows or category_mix),
        'filters': {
            'range': active_range,
            'start': date_range.start.isoformat() if date_range.start else None,
            'end': date_range.end.isoformat() if date_range.end else None,
        },
    }

    return render_template('reports.html', **context)
