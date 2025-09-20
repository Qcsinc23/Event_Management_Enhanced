import unittest
from datetime import datetime, timedelta

from app import app
from helpers import get_db


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


if __name__ == '__main__':
    unittest.main()
