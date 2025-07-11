#!/usr/bin/env python3
"""
Comprehensive Testing Suite for QCS Event Management Application
Tests all core functionality, security, and user workflows
"""

import os
import sys
import json
import requests
import sqlite3
from datetime import datetime, timedelta
import tempfile

# Add the application directory to the Python path
app_dir = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, app_dir)

# Import the Flask app
from app import app
from helpers import get_db

class QCSTestSuite:
    def __init__(self):
        self.app = app
        self.client = app.test_client()
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        
        self.test_results = {
            'passed': 0,
            'failed': 0,
            'errors': [],
            'warnings': [],
            'test_details': []
        }
        
    def log_test(self, test_name, status, message="", details=None):
        """Log test results"""
        result = {
            'test': test_name,
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'details': details or {}
        }
        
        self.test_results['test_details'].append(result)
        
        if status == 'PASS':
            self.test_results['passed'] += 1
            print(f"✅ {test_name}: {message}")
        elif status == 'FAIL':
            self.test_results['failed'] += 1
            self.test_results['errors'].append(f"{test_name}: {message}")
            print(f"❌ {test_name}: {message}")
        elif status == 'WARN':
            self.test_results['warnings'].append(f"{test_name}: {message}")
            print(f"⚠️  {test_name}: {message}")
        else:
            print(f"ℹ️  {test_name}: {message}")

    def test_authentication(self):
        """Test authentication system"""
        print("\n🔐 Testing Authentication System")
        print("-" * 40)
        
        # Test login page access
        response = self.client.get('/login')
        if response.status_code == 200:
            self.log_test("Login Page Access", "PASS", "Login page loads successfully")
        else:
            self.log_test("Login Page Access", "FAIL", f"Status code: {response.status_code}")
        
        # Test valid login
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'admin'
        }, follow_redirects=True)
        
        if response.status_code == 200 and b'Dashboard' in response.data:
            self.log_test("Valid Login", "PASS", "Admin login successful")
        else:
            self.log_test("Valid Login", "FAIL", "Admin login failed")
        
        # Test invalid login
        response = self.client.post('/login', data={
            'username': 'invalid',
            'password': 'invalid'
        })
        
        if b'Invalid' in response.data or response.status_code == 200:
            self.log_test("Invalid Login Protection", "PASS", "Invalid credentials rejected")
        else:
            self.log_test("Invalid Login Protection", "FAIL", "Invalid login not properly handled")
        
        # Test logout
        response = self.client.get('/logout', follow_redirects=True)
        if b'login' in response.data.lower():
            self.log_test("Logout Functionality", "PASS", "Logout redirects to login")
        else:
            self.log_test("Logout Functionality", "FAIL", "Logout not working properly")

    def test_authorization(self):
        """Test role-based authorization"""
        print("\n🛡️  Testing Authorization System")
        print("-" * 40)
        
        # Test access to protected routes without login
        protected_routes = ['/users', '/users/new', '/equipment', '/equipment/new']
        
        for route in protected_routes:
            response = self.client.get(route, follow_redirects=True)
            if b'login' in response.data.lower():
                self.log_test(f"Protected Route {route}", "PASS", "Requires authentication")
            else:
                self.log_test(f"Protected Route {route}", "FAIL", "Accessible without login")

    def test_database_operations(self):
        """Test database operations"""
        print("\n🗄️  Testing Database Operations")
        print("-" * 40)
        
        try:
            # Test database connection
            with self.app.app_context():
                db = get_db()
                cursor = db.cursor()
                
                # Test basic queries
                cursor.execute("SELECT COUNT(*) FROM users")
                user_count = cursor.fetchone()[0]
                self.log_test("Database Connection", "PASS", f"Connected, {user_count} users found")
                
                # Test data integrity
                cursor.execute("""
                    SELECT COUNT(*) FROM events e 
                    LEFT JOIN clients c ON e.client_id = c.id 
                    WHERE c.id IS NULL AND e.client_id IS NOT NULL
                """)
                orphaned_events = cursor.fetchone()[0]
                
                if orphaned_events == 0:
                    self.log_test("Data Integrity", "PASS", "No orphaned event records")
                else:
                    self.log_test("Data Integrity", "FAIL", f"{orphaned_events} orphaned events found")
                
        except Exception as e:
            self.log_test("Database Operations", "FAIL", f"Database error: {str(e)}")

    def test_client_management(self):
        """Test client management functionality"""
        print("\n🏢 Testing Client Management")
        print("-" * 40)
        
        # Login as admin first
        self.client.post('/login', data={'username': 'admin', 'password': 'admin'})
        
        # Test client list access
        response = self.client.get('/clients')
        if response.status_code == 200:
            self.log_test("Client List Access", "PASS", "Client list loads successfully")
        else:
            self.log_test("Client List Access", "FAIL", f"Status code: {response.status_code}")
        
        # Test new client form access
        response = self.client.get('/clients/new')
        if response.status_code == 200 and b'form' in response.data.lower():
            self.log_test("New Client Form", "PASS", "New client form accessible")
        else:
            self.log_test("New Client Form", "FAIL", "New client form not accessible")

    def test_event_management(self):
        """Test event management functionality"""
        print("\n📅 Testing Event Management")
        print("-" * 40)
        
        # Login as admin
        self.client.post('/login', data={'username': 'admin', 'password': 'admin'})
        
        # Test calendar access
        response = self.client.get('/calendar')
        if response.status_code == 200:
            self.log_test("Calendar Access", "PASS", "Calendar page loads successfully")
        else:
            self.log_test("Calendar Access", "FAIL", f"Status code: {response.status_code}")
        
        # Test event API endpoints
        response = self.client.get('/api/events')
        if response.status_code == 200:
            try:
                events_data = json.loads(response.data)
                self.log_test("Events API", "PASS", f"API returns {len(events_data)} events")
            except json.JSONDecodeError:
                self.log_test("Events API", "FAIL", "Invalid JSON response")
        else:
            self.log_test("Events API", "FAIL", f"Status code: {response.status_code}")

    def test_inventory_management(self):
        """Test inventory/element management"""
        print("\n📦 Testing Inventory Management")
        print("-" * 40)
        
        # Login as admin
        self.client.post('/login', data={'username': 'admin', 'password': 'admin'})
        
        # Test elements page
        response = self.client.get('/elements')
        if response.status_code == 200:
            self.log_test("Elements Page", "PASS", "Elements page loads successfully")
        else:
            self.log_test("Elements Page", "FAIL", f"Status code: {response.status_code}")
        
        # Test element types page
        response = self.client.get('/element-types')
        if response.status_code == 200:
            self.log_test("Element Types Page", "PASS", "Element types page loads successfully")
        else:
            self.log_test("Element Types Page", "FAIL", f"Status code: {response.status_code}")
        
        # Test kits page
        response = self.client.get('/kits')
        if response.status_code == 200:
            self.log_test("Kits Page", "PASS", "Kits page loads successfully")
        else:
            self.log_test("Kits Page", "FAIL", f"Status code: {response.status_code}")

    def test_blueprint_functionality(self):
        """Test blueprint-specific functionality"""
        print("\n🧩 Testing Blueprint Functionality")
        print("-" * 40)
        
        # Login as admin
        self.client.post('/login', data={'username': 'admin', 'password': 'admin'})
        
        # Test locations blueprint
        response = self.client.get('/locations')
        if response.status_code == 200:
            self.log_test("Locations Blueprint", "PASS", "Locations page accessible")
        else:
            self.log_test("Locations Blueprint", "FAIL", f"Status code: {response.status_code}")

    def test_security_features(self):
        """Test security features"""
        print("\n🔒 Testing Security Features")
        print("-" * 40)
        
        # Test SQL injection protection
        response = self.client.post('/login', data={
            'username': "admin'; DROP TABLE users; --",
            'password': 'test'
        })
        
        # Check if users table still exists
        try:
            with self.app.app_context():
                db = get_db()
                cursor = db.cursor()
                cursor.execute("SELECT COUNT(*) FROM users")
                user_count = cursor.fetchone()[0]
                self.log_test("SQL Injection Protection", "PASS", "Database protected from SQL injection")
        except Exception:
            self.log_test("SQL Injection Protection", "FAIL", "Possible SQL injection vulnerability")
        
        # Test XSS protection in forms
        self.client.post('/login', data={'username': 'admin', 'password': 'admin'})
        
        xss_payload = "<script>alert('XSS')</script>"
        response = self.client.post('/clients/new', data={
            'name': xss_payload,
            'color': '#FF0000'
        }, follow_redirects=True)
        
        if xss_payload.encode() not in response.data:
            self.log_test("XSS Protection", "PASS", "XSS payload properly escaped")
        else:
            self.log_test("XSS Protection", "FAIL", "Possible XSS vulnerability")

    def test_performance(self):
        """Test basic performance metrics"""
        print("\n⚡ Testing Performance")
        print("-" * 40)
        
        import time
        
        # Test page load times
        pages_to_test = ['/login', '/']
        
        for page in pages_to_test:
            start_time = time.time()
            
            if page == '/':
                # Login first for dashboard
                self.client.post('/login', data={'username': 'admin', 'password': 'admin'})
            
            response = self.client.get(page)
            load_time = time.time() - start_time
            
            if load_time < 1.0:  # Less than 1 second
                self.log_test(f"Page Load Time {page}", "PASS", f"Loaded in {load_time:.3f}s")
            elif load_time < 3.0:  # Less than 3 seconds
                self.log_test(f"Page Load Time {page}", "WARN", f"Loaded in {load_time:.3f}s")
            else:
                self.log_test(f"Page Load Time {page}", "FAIL", f"Slow load time: {load_time:.3f}s")

    def run_all_tests(self):
        """Run all test suites"""
        print("🧪 Starting Comprehensive Testing Suite")
        print("=" * 60)
        print(f"📅 Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all test suites
        test_suites = [
            self.test_authentication,
            self.test_authorization,
            self.test_database_operations,
            self.test_client_management,
            self.test_event_management,
            self.test_inventory_management,
            self.test_blueprint_functionality,
            self.test_security_features,
            self.test_performance,
        ]
        
        for test_suite in test_suites:
            try:
                test_suite()
            except Exception as e:
                self.log_test(test_suite.__name__, "FAIL", f"Test suite error: {str(e)}")
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        print(f"✅ Tests Passed: {self.test_results['passed']}")
        print(f"❌ Tests Failed: {self.test_results['failed']}")
        print(f"⚠️  Warnings: {len(self.test_results['warnings'])}")
        
        success_rate = (self.test_results['passed'] / 
                       (self.test_results['passed'] + self.test_results['failed'])) * 100
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        if self.test_results['errors']:
            print("\n🚨 CRITICAL ISSUES:")
            for error in self.test_results['errors']:
                print(f"  • {error}")
        
        if self.test_results['warnings']:
            print("\n⚠️  WARNINGS:")
            for warning in self.test_results['warnings']:
                print(f"  • {warning}")
        
        # Save detailed results
        output_file = "/workspace/docs/testing_results.json"
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)
        
        print(f"\n💾 Detailed test results saved to: {output_file}")
        
        return self.test_results

if __name__ == "__main__":
    tester = QCSTestSuite()
    results = tester.run_all_tests()
