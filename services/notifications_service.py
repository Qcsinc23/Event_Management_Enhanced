"""Notification generation for dashboard and header alerts."""
from datetime import datetime, timedelta, date
from flask import url_for

SEVERITY_PRIORITY = {
    'danger': 0,
    'warning': 1,
    'info': 2,
    'success': 3,
}


def _relative_time(date_str, date_obj=None):
    if not date_str:
        return ""
    base = date_obj or datetime.now()
    if isinstance(date_str, datetime):
        target = date_str
    elif isinstance(date_str, date):
        target = datetime.combine(date_str, datetime.min.time())
    else:
        try:
            target = datetime.strptime(str(date_str), '%Y-%m-%d')
        except ValueError:
            return str(date_str)
    delta = target.date() - base.date()
    days = delta.days
    if days == 0:
        return 'Today'
    if days == 1:
        return 'Tomorrow'
    if days == -1:
        return 'Yesterday'
    if days > 1:
        return f'In {days} days'
    return f'{abs(days)} days ago'


def fetch_notifications(db, dismissed_ids=None, limit=10):
    """Build a list of actionable notifications."""
    dismissed_ids = set(dismissed_ids or [])
    now = datetime.now()
    today = now.date()
    notifications = []

    # Overdue tasks
    overdue_rows = db.execute(
        '''SELECT t.id, t.description, t.due_date, e.event_name, e.event_id
           FROM event_tasks t
           JOIN events e ON t.event_id = e.event_id
           WHERE t.status != 'completed' AND t.due_date IS NOT NULL AND t.due_date < ?
           ORDER BY t.due_date ASC LIMIT 5''',
        (today.strftime('%Y-%m-%d'),)
    ).fetchall()
    for row in overdue_rows:
        notif_id = f"task-overdue-{row['id']}"
        due_str = row['due_date']
        if isinstance(due_str, (datetime, date)):
            due_str_fmt = due_str.strftime('%Y-%m-%d')
        else:
            due_str_fmt = str(due_str)
        notifications.append({
            'id': notif_id,
            'title': 'Task Overdue',
            'description': row['description'],
            'time': _relative_time(row['due_date'], now),
            'severity': 'danger',
            'link': url_for('tasks.event_tasks', event_id=row['event_id']),
            'category': 'tasks',
            'meta': row['event_name'],
            'timestamp': due_str_fmt + ' 00:00:00',
        })

    # Tasks due soon (next 3 days)
    soon_rows = db.execute(
        '''SELECT t.id, t.description, t.due_date, e.event_name, e.event_id
           FROM event_tasks t
           JOIN events e ON t.event_id = e.event_id
           WHERE t.status != 'completed' AND t.due_date IS NOT NULL
             AND t.due_date BETWEEN ? AND ?
           ORDER BY t.due_date ASC LIMIT 5''',
        (today.strftime('%Y-%m-%d'), (today + timedelta(days=3)).strftime('%Y-%m-%d'))
    ).fetchall()
    for row in soon_rows:
        notif_id = f"task-upcoming-{row['id']}"
        due_str = row['due_date']
        if isinstance(due_str, (datetime, date)):
            due_str_fmt = due_str.strftime('%Y-%m-%d')
        else:
            due_str_fmt = str(due_str)
        notifications.append({
            'id': notif_id,
            'title': 'Task Due Soon',
            'description': row['description'],
            'time': _relative_time(row['due_date'], now),
            'severity': 'warning',
            'link': url_for('tasks.event_tasks', event_id=row['event_id']),
            'category': 'tasks',
            'meta': row['event_name'],
            'timestamp': due_str_fmt + ' 00:00:00',
        })

    # Low stock equipment/elements
    low_stock_rows = db.execute(
        '''SELECT e.element_id, e.item_description, e.quantity, t.type_name
           FROM elements e
           JOIN element_types t ON e.type_id = t.type_id
           WHERE e.quantity IS NOT NULL AND e.quantity < 5
           ORDER BY e.quantity ASC LIMIT 5'''
    ).fetchall()
    for row in low_stock_rows:
        notif_id = f"stock-low-{row['element_id']}"
        notifications.append({
            'id': notif_id,
            'title': 'Low Stock Alert',
            'description': f"{row['item_description']} has only {row['quantity']} left",
            'time': 'Needs restock',
            'severity': 'warning',
            'link': url_for('elements'),
            'category': 'inventory',
            'meta': row['type_name'],
            'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
        })

    # Recently completed events (last 48 hours)
    completed_rows = db.execute(
        '''SELECT event_id, event_name, last_updated
           FROM events
           WHERE status = 'completed' AND last_updated IS NOT NULL
           ORDER BY last_updated DESC LIMIT 5'''
    ).fetchall()
    for row in completed_rows:
        try:
            completed_dt = datetime.strptime(row['last_updated'], '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            completed_dt = now
        if (now - completed_dt) > timedelta(hours=48):
            continue
        notif_id = f"event-completed-{row['event_id']}"
        notifications.append({
            'id': notif_id,
            'title': 'Event Completed',
            'description': row['event_name'],
            'time': _relative_time(completed_dt.strftime('%Y-%m-%d'), now),
            'severity': 'info',
            'link': url_for('calendar.view_event', event_id=row['event_id']),
            'category': 'events',
            'meta': 'Completed',
            'timestamp': completed_dt.strftime('%Y-%m-%d %H:%M:%S'),
        })

    # Filter dismissed
    notifications = [n for n in notifications if n['id'] not in dismissed_ids]

    notifications = sorted(
        notifications,
        key=lambda n: (
            SEVERITY_PRIORITY.get(n['severity'], 99),
            n['timestamp']
        )
    )

    return notifications[:limit]
