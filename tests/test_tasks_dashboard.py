import unittest
from datetime import datetime, timedelta

from app import app
from helpers import get_db
from services.notifications_service import fetch_notifications


class TaskDashboardTestCase(unittest.TestCase):
    def setUp(self):
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.client.post('/login', data={'username': 'admin', 'password': 'admin'}, follow_redirects=True)

        self.today = datetime.now().date()
        self.cleanup_ids = {}

        with app.app_context():
            db = get_db()
            # Create a temporary client
            db.execute(
                '''INSERT INTO clients (name, color, contact_person, email)
                   VALUES (?, ?, ?, ?)''',
                ('Test Automation Client', '#123456', 'Test User', 'test@example.com')
            )
            client_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
            self.cleanup_ids['client_id'] = client_id

            # Create a temporary event
            event_date = self.today.strftime('%Y-%m-%d')
            db.execute(
                '''INSERT INTO events (event_name, client_id, event_date, status)
                   VALUES (?, ?, ?, ?)''',
                ('Automation Event', client_id, event_date, 'booked')
            )
            event_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
            self.cleanup_ids['event_id'] = event_id

            due_today = self.today.strftime('%Y-%m-%d')
            due_tomorrow = (self.today + timedelta(days=1)).strftime('%Y-%m-%d')
            overdue = (self.today - timedelta(days=1)).strftime('%Y-%m-%d')

            task_ids = {}
            tasks = [
                ('Prepare materials', due_today, 'pending'),
                ('Confirm logistics', due_tomorrow, 'in_progress'),
                ('Archive photos', overdue, 'pending'),
            ]
            for desc, due, status in tasks:
                db.execute(
                    '''INSERT INTO event_tasks (event_id, description, due_date, status, is_completed)
                       VALUES (?, ?, ?, ?, ?)''',
                    (event_id, desc, due, status, 1 if status == 'completed' else 0)
                )
            db.commit()

            rows = db.execute('SELECT id, description FROM event_tasks WHERE event_id = ?', (event_id,)).fetchall()
            for row in rows:
                if row['description'] == 'Archive photos':
                    task_ids['overdue'] = row['id']
                elif row['description'] == 'Confirm logistics':
                    task_ids['upcoming'] = row['id']
            self.cleanup_ids['task_ids'] = task_ids

    def tearDown(self):
        with app.app_context():
            db = get_db()
            if 'event_id' in self.cleanup_ids:
                db.execute('DELETE FROM event_tasks WHERE event_id = ?', (self.cleanup_ids['event_id'],))
                db.execute('DELETE FROM equipment_assignments WHERE event_id = ?', (self.cleanup_ids['event_id'],))
                db.execute('DELETE FROM events WHERE event_id = ?', (self.cleanup_ids['event_id'],))
            if 'client_id' in self.cleanup_ids:
                db.execute('DELETE FROM clients WHERE id = ?', (self.cleanup_ids['client_id'],))
            db.commit()

    def test_kanban_board_renders(self):
        resp = self.client.get(f"/events/{self.cleanup_ids['event_id']}/tasks")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'kanban-column', resp.data)
        self.assertIn(b'Tasks At a Glance', self.client.get('/').data)

    def test_status_update_api(self):
        with app.app_context():
            db = get_db()
            task_id = db.execute(
                'SELECT id FROM event_tasks WHERE event_id = ? ORDER BY id LIMIT 1',
                (self.cleanup_ids['event_id'],)
            ).fetchone()[0]

        response = self.client.patch(
            f"/api/tasks/{task_id}/status",
            json={'status': 'completed'},
            headers={'X-Requested-With': 'XMLHttpRequest'}
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['success'])
        self.assertIn('summary', payload)
        self.assertGreaterEqual(payload['summary']['completed'], 1)

    def test_notifications_panel_and_ack(self):
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Notifications', resp.data)
        self.assertIn(b'notification-item', resp.data)

        task_ids = self.cleanup_ids.get('task_ids', {})
        ids_to_ack = []
        if 'overdue' in task_ids:
            ids_to_ack.append(f"task-overdue-{task_ids['overdue']}")
        if 'upcoming' in task_ids:
            ids_to_ack.append(f"task-upcoming-{task_ids['upcoming']}")

        with self.client.session_transaction() as sess:
            dismissed = set(sess.get('dismissed_notifications', []))

        with app.app_context():
            db = get_db()
            all_notifications = fetch_notifications(db, dismissed_ids=dismissed)
            if not ids_to_ack:
                ids_to_ack = [n['id'] for n in all_notifications]
            else:
                ids_to_ack.extend(n['id'] for n in all_notifications if n['id'] not in ids_to_ack)

        ack_resp = self.client.post(
            '/notifications/ack',
            json={'ids': ids_to_ack},
            headers={'X-Requested-With': 'XMLHttpRequest'}
        )
        self.assertEqual(ack_resp.status_code, 200)
        follow_resp = self.client.get('/')
        self.assertIn(b'data-count="0"', follow_resp.data)


if __name__ == '__main__':
    unittest.main()
