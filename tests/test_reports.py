import unittest
from datetime import datetime, timedelta

from app import app
from helpers import get_db


class ReportsViewTestCase(unittest.TestCase):
    def setUp(self):
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        self.client.post('/login', data={'username': 'admin', 'password': 'admin'}, follow_redirects=True)

        self.today = datetime.now().date()
        self.cleanup = {}

        with app.app_context():
            db = get_db()

            # Clients
            db.execute(
                """INSERT INTO clients (name, color, contact_person, email)
                       VALUES (?, ?, ?, ?)""",
                ('Client Alpha', '#123456', 'Alice Planner', 'alpha@example.com'),
            )
            client_alpha = db.execute('SELECT last_insert_rowid()').fetchone()[0]

            db.execute(
                """INSERT INTO clients (name, color, contact_person, email)
                       VALUES (?, ?, ?, ?)""",
                ('Client Beta', '#654321', 'Bob Manager', 'beta@example.com'),
            )
            client_beta = db.execute('SELECT last_insert_rowid()').fetchone()[0]

            # Category for events
            db.execute(
                "INSERT INTO event_categories (name, color) VALUES (?, ?)",
                ('Corporate', '#2dc653'),
            )
            category_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]

            # Events
            recent_date = self.today.strftime('%Y-%m-%d')
            old_date = (self.today - timedelta(days=120)).strftime('%Y-%m-%d')

            db.execute(
                """INSERT INTO events (event_name, client_id, event_date, status, category_id)
                       VALUES (?, ?, ?, ?, ?)""",
                ('Alpha Launch', client_alpha, recent_date, 'completed', category_id),
            )
            event_recent = db.execute('SELECT last_insert_rowid()').fetchone()[0]

            db.execute(
                """INSERT INTO events (event_name, client_id, event_date, status, category_id)
                       VALUES (?, ?, ?, ?, ?)""",
                ('Beta Summit', client_beta, old_date, 'completed', category_id),
            )
            event_old = db.execute('SELECT last_insert_rowid()').fetchone()[0]

            # Equipment
            db.execute(
                "INSERT INTO equipment (name, quantity) VALUES (?, ?)",
                ('LED Wall', 8),
            )
            equipment_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]

            # Assignments
            db.execute(
                """INSERT INTO equipment_assignments (event_id, equipment_id, quantity)
                       VALUES (?, ?, ?)""",
                (event_recent, equipment_id, 4),
            )
            db.execute(
                """INSERT INTO equipment_assignments (event_id, equipment_id, quantity)
                       VALUES (?, ?, ?)""",
                (event_old, equipment_id, 2),
            )

            # Invoices
            db.execute(
                """INSERT INTO invoices (event_id, client_id, amount, issue_date, status)
                       VALUES (?, ?, ?, ?, ?)""",
                (event_recent, client_alpha, 1000.00, recent_date, 'paid'),
            )
            db.execute(
                """INSERT INTO invoices (event_id, client_id, amount, issue_date, status)
                       VALUES (?, ?, ?, ?, ?)""",
                (event_old, client_beta, 500.00, old_date, 'unpaid'),
            )

            db.commit()

            self.cleanup.update(
                {
                    'clients': [client_alpha, client_beta],
                    'events': [event_recent, event_old],
                    'equipment': [equipment_id],
                    'category_id': category_id,
                }
            )

    def tearDown(self):
        with app.app_context():
            db = get_db()
            for event_id in self.cleanup.get('events', []):
                db.execute('DELETE FROM equipment_assignments WHERE event_id = ?', (event_id,))
                db.execute('DELETE FROM invoices WHERE event_id = ?', (event_id,))
                db.execute('DELETE FROM events WHERE event_id = ?', (event_id,))
            for client_id in self.cleanup.get('clients', []):
                db.execute('DELETE FROM clients WHERE id = ?', (client_id,))
            for equipment_id in self.cleanup.get('equipment', []):
                db.execute('DELETE FROM equipment WHERE id = ?', (equipment_id,))
            if self.cleanup.get('category_id'):
                db.execute('DELETE FROM event_categories WHERE id = ?', (self.cleanup['category_id'],))
            db.commit()

    def test_reports_overview_shows_recent_activity(self):
        response = self.client.get('/reports')
        self.assertEqual(response.status_code, 200)
        html = response.data

        self.assertIn(b'Reports &amp; Analytics', html)
        self.assertIn(b'Client Alpha', html)
        self.assertNotIn(b'Client Beta', html)
        self.assertIn(b'$1000.00', html)
        self.assertIn(b'Collected', html)
        self.assertIn(b'Equipment Utilisation', html)

    def test_reports_all_range_includes_historic_data(self):
        response = self.client.get('/reports?range=all')
        self.assertEqual(response.status_code, 200)
        html = response.data

        self.assertIn(b'Client Alpha', html)
        self.assertIn(b'Client Beta', html)
        self.assertIn(b'$500.00', html)
        self.assertIn(b'"period"', html)  # Chart payload rendered as JSON

    def test_reports_custom_range_handles_reversed_dates(self):
        future = (self.today + timedelta(days=1)).strftime('%Y-%m-%d')
        past = (self.today - timedelta(days=1)).strftime('%Y-%m-%d')
        response = self.client.get(f'/reports?start={future}&end={past}')
        self.assertEqual(response.status_code, 200)
        # Should gracefully swap and still render content
        self.assertIn(b'Reports &amp; Analytics', response.data)


if __name__ == '__main__':
    unittest.main()
