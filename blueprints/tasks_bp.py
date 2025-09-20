"""Task management blueprint with Kanban-style views."""
from datetime import datetime, date
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort

from helpers import get_db, login_required, role_required


tasks_bp = Blueprint('tasks', __name__, url_prefix='')

TASK_STATUS_CONFIG = [
    ('pending', 'To Do'),
    ('in_progress', 'In Progress'),
    ('completed', 'Completed'),
]
STATUS_LOOKUP = dict(TASK_STATUS_CONFIG)


def _serialize_task(row, today):
    due_date_obj = None
    due_value = row['due_date']
    if due_value:
        if isinstance(due_value, datetime):
            due_date_obj = due_value.date()
        elif isinstance(due_value, date):
            due_date_obj = due_value
        else:
            try:
                due_date_obj = datetime.strptime(due_value, '%Y-%m-%d').date()
            except (ValueError, TypeError):
                due_date_obj = None

    is_completed = bool(row['is_completed']) or row['status'] == 'completed'
    is_overdue = due_date_obj and due_date_obj < today and not is_completed
    is_upcoming = due_date_obj and 0 <= (due_date_obj - today).days <= 2 and not is_completed

    assigned_display = row['assigned_full_name'] or row['assigned_username']

    due_date_value = (
        due_date_obj.strftime('%Y-%m-%d') if isinstance(due_date_obj, (datetime, date)) else due_value
    )

    return {
        'id': row['id'],
        'event_id': row['event_id'],
        'description': row['description'],
        'status': row['status'],
        'status_label': STATUS_LOOKUP.get(row['status'], row['status'].title()),
        'due_date': due_date_value,
        'assigned_to': row['assigned_to'],
        'assigned_display': assigned_display,
        'is_completed': is_completed,
        'is_overdue': is_overdue,
        'is_upcoming': is_upcoming,
    }


def _task_summary(tasks):
    total = len(tasks)
    completed = sum(1 for task in tasks if task['status'] == 'completed' or task['is_completed'])
    percent = int((completed / total) * 100) if total else 0
    counts = {status: 0 for status, _ in TASK_STATUS_CONFIG}
    for task in tasks:
        counts[task['status']] = counts.get(task['status'], 0) + 1
    return {
        'total': total,
        'completed': completed,
        'percent': percent,
        'counts': counts,
    }


@tasks_bp.route('/events/<int:event_id>/tasks')
@login_required
def event_tasks(event_id):
    """Kanban view of tasks for an event."""
    db = get_db()

    event = db.execute(
        '''SELECT e.*, c.name AS client_name
           FROM events e
           LEFT JOIN clients c ON e.client_id = c.id
           WHERE e.event_id = ?''',
        (event_id,)
    ).fetchone()
    if event is None:
        abort(404)

    task_rows = db.execute(
        '''SELECT t.*, u.username AS assigned_username, u.full_name AS assigned_full_name
           FROM event_tasks t
           LEFT JOIN users u ON t.assigned_to = u.id
           WHERE t.event_id = ?
           ORDER BY CASE t.status WHEN 'pending' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,
                    t.is_completed,
                    COALESCE(t.due_date, ''),
                    t.id''',
        (event_id,)
    ).fetchall()

    today = date.today()
    tasks = [_serialize_task(row, today) for row in task_rows]
    summary = _task_summary(tasks)

    status_columns = []
    for status, label in TASK_STATUS_CONFIG:
        status_columns.append({
            'key': status,
            'label': label,
            'tasks': [task for task in tasks if task['status'] == status],
        })

    users = db.execute('SELECT id, username, full_name FROM users ORDER BY username').fetchall()

    return render_template(
        'event_tasks.html',
        event=event,
        status_columns=status_columns,
        users=users,
        summary=summary,
        status_config=TASK_STATUS_CONFIG,
    )


@tasks_bp.route('/events/<int:event_id>/tasks/add', methods=['POST'])
@login_required
def add_event_task(event_id):
    db = get_db()

    event = db.execute('SELECT event_id FROM events WHERE event_id = ?', (event_id,)).fetchone()
    if event is None:
        abort(404)

    description = request.form['description']
    due_date = request.form.get('due_date', '') or None
    assigned_to = request.form.get('assigned_to', '') or None
    status = request.form.get('status', 'pending')
    if status not in STATUS_LOOKUP:
        status = 'pending'

    if not description:
        flash('Task description is required', 'danger')
        return redirect(url_for('tasks.event_tasks', event_id=event_id))

    db.execute(
        '''INSERT INTO event_tasks (event_id, description, due_date, assigned_to, status, is_completed)
           VALUES (?, ?, ?, ?, ?, ?)''',
        (event_id, description, due_date, assigned_to, status, 1 if status == 'completed' else 0)
    )
    db.commit()
    flash('Task added successfully', 'success')
    return redirect(url_for('tasks.event_tasks', event_id=event_id))


@tasks_bp.route('/tasks/<int:task_id>/edit', methods=['POST'])
@login_required
def edit_task(task_id):
    db = get_db()
    task = db.execute('SELECT event_id FROM event_tasks WHERE id = ?', (task_id,)).fetchone()
    if task is None:
        abort(404)

    description = request.form['description']
    due_date = request.form.get('due_date', '') or None
    assigned_to = request.form.get('assigned_to', '') or None
    status = request.form.get('status', 'pending')
    if status not in STATUS_LOOKUP:
        status = 'pending'

    if not description:
        flash('Task description is required', 'danger')
        return redirect(url_for('tasks.event_tasks', event_id=task['event_id']))

    db.execute(
        '''UPDATE event_tasks
           SET description = ?, due_date = ?, assigned_to = ?, status = ?, is_completed = ?
           WHERE id = ?''',
        (description, due_date, assigned_to, status, 1 if status == 'completed' else 0, task_id)
    )
    db.commit()
    flash('Task updated successfully', 'success')
    return redirect(url_for('tasks.event_tasks', event_id=task['event_id']))


@tasks_bp.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    db = get_db()
    task = db.execute('SELECT event_id FROM event_tasks WHERE id = ?', (task_id,)).fetchone()
    if task is None:
        abort(404)

    db.execute('DELETE FROM event_tasks WHERE id = ?', (task_id,))
    db.commit()
    flash('Task deleted successfully', 'success')
    return redirect(url_for('tasks.event_tasks', event_id=task['event_id']))


@tasks_bp.route('/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    db = get_db()
    task = db.execute('SELECT event_id, is_completed FROM event_tasks WHERE id = ?', (task_id,)).fetchone()
    if task is None:
        abort(404)

    is_completed = not bool(task['is_completed'])
    db.execute(
        'UPDATE event_tasks SET is_completed = ?, status = ? WHERE id = ?',
        (1 if is_completed else 0, 'completed' if is_completed else 'pending', task_id)
    )
    db.commit()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'is_completed': is_completed})

    return redirect(url_for('tasks.event_tasks', event_id=task['event_id']))


@tasks_bp.route('/api/events/<int:event_id>/tasks')
@login_required
def api_event_tasks(event_id):
    db = get_db()
    event = db.execute('SELECT event_id FROM events WHERE event_id = ?', (event_id,)).fetchone()
    if event is None:
        return jsonify({'error': 'Event not found'}), 404

    task_rows = db.execute(
        '''SELECT t.*, u.username AS assigned_username, u.full_name AS assigned_full_name
           FROM event_tasks t
           LEFT JOIN users u ON t.assigned_to = u.id
           WHERE t.event_id = ?
           ORDER BY CASE t.status WHEN 'pending' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,
                    t.is_completed,
                    COALESCE(t.due_date, ''),
                    t.id''',
        (event_id,)
    ).fetchall()

    today = date.today()
    tasks = [_serialize_task(row, today) for row in task_rows]
    return jsonify(tasks)


@tasks_bp.route('/api/tasks/<int:task_id>/status', methods=['PATCH'])
@login_required
def api_update_task_status(task_id):
    db = get_db()
    task = db.execute('SELECT event_id FROM event_tasks WHERE id = ?', (task_id,)).fetchone()
    if task is None:
        return jsonify({'success': False, 'message': 'Task not found'}), 404

    payload = request.get_json(silent=True) or {}
    status = payload.get('status')
    if status not in STATUS_LOOKUP:
        return jsonify({'success': False, 'message': 'Invalid status'}), 400

    due_date = payload.get('due_date')
    assigned_to = payload.get('assigned_to')

    db.execute(
        'UPDATE event_tasks SET status = ?, is_completed = ?, due_date = COALESCE(?, due_date), assigned_to = COALESCE(?, assigned_to) WHERE id = ?',
        (status, 1 if status == 'completed' else 0, due_date, assigned_to, task_id)
    )
    db.commit()

    task_rows = db.execute(
        '''SELECT t.*, u.username AS assigned_username, u.full_name AS assigned_full_name
           FROM event_tasks t
           LEFT JOIN users u ON t.assigned_to = u.id
           WHERE t.event_id = ?''',
        (task['event_id'],)
    ).fetchall()

    today = date.today()
    tasks = [_serialize_task(row, today) for row in task_rows]
    summary = _task_summary(tasks)

    return jsonify({'success': True, 'summary': summary})


@tasks_bp.route('/api/tasks/<int:task_id>/toggle', methods=['POST'])
@login_required
def api_toggle_task(task_id):
    db = get_db()
    task = db.execute('SELECT * FROM event_tasks WHERE id = ?', (task_id,)).fetchone()
    if task is None:
        return jsonify({'error': 'Task not found'}), 404

    is_completed = not bool(task['is_completed'])
    new_status = 'completed' if is_completed else 'pending'

    db.execute(
        'UPDATE event_tasks SET is_completed = ?, status = ? WHERE id = ?',
        (1 if is_completed else 0, new_status, task_id)
    )
    db.commit()

    tasks = db.execute(
        'SELECT * FROM event_tasks WHERE event_id = ?',
        (task['event_id'],)
    ).fetchall()

    total_tasks = len(tasks)
    completed_tasks = sum(1 for t in tasks if t['is_completed'])
    completion_percentage = int((completed_tasks / total_tasks) * 100) if total_tasks > 0 else 0

    return jsonify({
        'success': True,
        'is_completed': is_completed,
        'status': new_status,
        'completion_percentage': completion_percentage
    })


def task_count_processor():
    def get_event_tasks_count(event_id):
        db = get_db()
        counts = db.execute(
            '''SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN is_completed = 1 THEN 1 ELSE 0 END) as completed
               FROM event_tasks 
               WHERE event_id = ?''',
            (event_id,)
        ).fetchone()

        return {
            'total': counts['total'] or 0,
            'completed': counts['completed'] or 0
        }

    return dict(get_event_tasks_count=get_event_tasks_count)
