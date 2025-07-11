#!/usr/bin/env python3
"""
QCS Event Management Application - Health Check Script
Verify application health and system status
"""

import os
import sys
import sqlite3
import requests
import json
from datetime import datetime
from pathlib import Path

def check_files():
    """Check if essential files exist"""
    print("📂 Checking application files...")
    
    essential_files = [
        'app.py',
        'helpers.py',
        'database.db',
        'requirements.txt',
        'templates/login.html',
        'static/style.css',
        'blueprints/__init__.py'
    ]
    
    missing_files = []
    for file in essential_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing files: {', '.join(missing_files)}")
        return False
    else:
        print(f"✅ All {len(essential_files)} essential files found")
        return True

def check_database():
    """Check database connectivity and integrity"""
    print("\n🗄️  Checking database...")
    
    if not os.path.exists('database.db'):
        print("❌ Database file not found")
        return False
    
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Check if essential tables exist
        essential_tables = ['users', 'clients', 'events', 'elements']
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row[0] for row in cursor.fetchall()]
        
        missing_tables = [table for table in essential_tables if table not in existing_tables]
        if missing_tables:
            print(f"❌ Missing database tables: {', '.join(missing_tables)}")
            conn.close()
            return False
        
        # Check user count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        # Check for admin user
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cursor.fetchone()[0]
        
        conn.close()
        
        print(f"✅ Database accessible with {user_count} users ({admin_count} admin)")
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False

def check_dependencies():
    """Check if required dependencies are installed"""
    print("\n📦 Checking dependencies...")
    
    required_packages = [
        'flask',
        'werkzeug',
        'jinja2',
        'bcrypt',
        'weasyprint'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("💡 Install with: pip install -r requirements.txt")
        return False
    else:
        print(f"✅ All {len(required_packages)} key dependencies available")
        return True

def check_application_import():
    """Check if the Flask application can be imported"""
    print("\n🐍 Checking application import...")
    
    try:
        # Add current directory to path for import
        sys.path.insert(0, '.')
        from app import app
        print("✅ Flask application imports successfully")
        return True
    except ImportError as e:
        print(f"❌ Application import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Application error: {e}")
        return False

def check_running_application(host='localhost', port=5004):
    """Check if application is running and responding"""
    print(f"\n🌐 Checking running application at {host}:{port}...")
    
    try:
        response = requests.get(f'http://{host}:{port}/login', timeout=5)
        if response.status_code == 200:
            print("✅ Application is running and responding")
            return True
        else:
            print(f"⚠️  Application responding with status code: {response.status_code}")
            return False
    except requests.ConnectionError:
        print("❌ Application not reachable (not running?)")
        return False
    except requests.Timeout:
        print("❌ Application not responding (timeout)")
        return False
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False

def check_configuration():
    """Check application configuration"""
    print("\n⚙️  Checking configuration...")
    
    issues = []
    
    # Check secret key
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        issues.append("SECRET_KEY environment variable not set")
    elif secret_key in ['dev_key_replace_in_production', 'dev_key_please_change_in_production']:
        issues.append("SECRET_KEY still using default value (security risk)")
    
    # Check Flask environment
    flask_env = os.environ.get('FLASK_ENV', 'development')
    if flask_env == 'production':
        print("✅ Running in production mode")
    else:
        print("⚠️  Running in development mode")
    
    if issues:
        for issue in issues:
            print(f"⚠️  {issue}")
        return False
    else:
        print("✅ Configuration looks good")
        return True

def generate_health_report():
    """Generate a comprehensive health report"""
    print("\n📊 Generating health report...")
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'checks': {}
    }
    
    # Run all health checks
    checks = [
        ('files', check_files),
        ('database', check_database),
        ('dependencies', check_dependencies),
        ('application_import', check_application_import),
        ('configuration', check_configuration),
    ]
    
    passed_checks = 0
    for check_name, check_func in checks:
        result = check_func()
        report['checks'][check_name] = {
            'passed': result,
            'timestamp': datetime.now().isoformat()
        }
        if result:
            passed_checks += 1
    
    # Optional running application check
    if '--check-running' in sys.argv or '--full' in sys.argv:
        running_result = check_running_application()
        report['checks']['running_application'] = {
            'passed': running_result,
            'timestamp': datetime.now().isoformat()
        }
        if running_result:
            passed_checks += 1
    
    report['summary'] = {
        'total_checks': len(report['checks']),
        'passed_checks': passed_checks,
        'success_rate': (passed_checks / len(report['checks'])) * 100,
        'overall_status': 'healthy' if passed_checks == len(report['checks']) else 'issues_found'
    }
    
    return report

def main():
    """Main health check function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='QCS Event Management Health Check')
    parser.add_argument('--check-running', action='store_true',
                       help='Check if application is currently running')
    parser.add_argument('--full', action='store_true',
                       help='Run all checks including running application')
    parser.add_argument('--json', action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('--save-report', type=str,
                       help='Save detailed report to file')
    
    args = parser.parse_args()
    
    if not args.json:
        print("🏥 QCS Event Management Health Check")
        print("=" * 50)
    
    # Change to application directory
    app_dir = Path(__file__).parent.parent
    os.chdir(app_dir)
    
    # Generate health report
    report = generate_health_report()
    
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        # Display summary
        print("\n" + "=" * 50)
        print("📋 HEALTH CHECK SUMMARY")
        print("=" * 50)
        print(f"✅ Checks passed: {report['summary']['passed_checks']}/{report['summary']['total_checks']}")
        print(f"📈 Success rate: {report['summary']['success_rate']:.1f}%")
        print(f"🏥 Overall status: {report['summary']['overall_status'].replace('_', ' ').title()}")
        
        # Show failed checks
        failed_checks = [name for name, result in report['checks'].items() if not result['passed']]
        if failed_checks:
            print(f"\n❌ Failed checks: {', '.join(failed_checks)}")
            print("\n💡 Troubleshooting tips:")
            if 'files' in failed_checks:
                print("   • Run: python scripts/setup.py")
            if 'dependencies' in failed_checks:
                print("   • Run: pip install -r requirements.txt")
            if 'database' in failed_checks:
                print("   • Run: python init_db.py")
            if 'running_application' in failed_checks:
                print("   • Start application: python run.py")
        else:
            print("\n🎉 All health checks passed!")
    
    # Save report if requested
    if args.save_report:
        with open(args.save_report, 'w') as f:
            json.dump(report, f, indent=2)
        if not args.json:
            print(f"\n💾 Report saved to: {args.save_report}")
    
    # Exit with appropriate code
    sys.exit(0 if report['summary']['overall_status'] == 'healthy' else 1)

if __name__ == "__main__":
    main()
