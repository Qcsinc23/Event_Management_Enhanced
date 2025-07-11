#!/usr/bin/env python3
"""
QCS Event Management Application - Setup Script
Automated setup and initialization for the application
"""

import os
import sys
import subprocess
import sqlite3
from pathlib import Path

def check_python_version():
    """Check if Python version is 3.9 or higher"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print("❌ Error: Python 3.9 or higher is required")
        print(f"   Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    print(f"✅ Python version: {version.major}.{version.minor}.{version.micro}")
    return True

def create_virtual_environment():
    """Create and activate virtual environment"""
    print("\n🔧 Setting up virtual environment...")
    
    try:
        if not os.path.exists('venv'):
            subprocess.run([sys.executable, '-m', 'venv', 'venv'], check=True)
            print("✅ Virtual environment created")
        else:
            print("✅ Virtual environment already exists")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create virtual environment: {e}")
        return False

def install_dependencies():
    """Install required dependencies"""
    print("\n📦 Installing dependencies...")
    
    # Determine the correct pip path
    if os.name == 'nt':  # Windows
        pip_path = os.path.join('venv', 'Scripts', 'pip')
    else:  # Unix/Linux/macOS
        pip_path = os.path.join('venv', 'bin', 'pip')
    
    try:
        subprocess.run([pip_path, 'install', '-r', 'requirements.txt'], check=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        print("💡 Try running: pip install -r requirements.txt")
        return False
    except FileNotFoundError:
        print("⚠️  Virtual environment pip not found, using system pip")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], check=True)
            print("✅ Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False

def check_database():
    """Check if database exists and is accessible"""
    print("\n🗄️  Checking database...")
    
    if os.path.exists('database.db'):
        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            conn.close()
            print(f"✅ Database found with {user_count} users")
            return True
        except sqlite3.Error as e:
            print(f"❌ Database error: {e}")
            return False
    else:
        print("⚠️  Database not found, will need to initialize")
        return False

def initialize_database():
    """Initialize database if needed"""
    print("\n🔧 Initializing database...")
    
    try:
        subprocess.run([sys.executable, 'init_db.py'], check=True)
        print("✅ Database initialized successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to initialize database: {e}")
        return False

def create_environment_file():
    """Create .env file template"""
    print("\n⚙️  Creating environment configuration...")
    
    env_content = """# QCS Event Management Application Environment Variables
# Copy this file to .env and update the values for your environment

# Secret key for Flask sessions (CHANGE THIS IN PRODUCTION!)
SECRET_KEY=your-super-secret-key-change-this-in-production

# Flask environment (development/production)
FLASK_ENV=development
FLASK_DEBUG=True

# Database configuration
DATABASE_PATH=database.db

# Application host and port
HOST=0.0.0.0
PORT=5004

# Security settings (for production)
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
WTF_CSRF_ENABLED=True
"""
    
    if not os.path.exists('.env.template'):
        with open('.env.template', 'w') as f:
            f.write(env_content)
        print("✅ Environment template created (.env.template)")
    else:
        print("✅ Environment template already exists")

def main():
    """Main setup function"""
    print("🚀 QCS Event Management Application Setup")
    print("=" * 50)
    
    # Change to the application directory
    app_dir = Path(__file__).parent.parent
    os.chdir(app_dir)
    print(f"📂 Working directory: {os.getcwd()}")
    
    # Setup steps
    steps = [
        ("Checking Python version", check_python_version),
        ("Creating virtual environment", create_virtual_environment),
        ("Installing dependencies", install_dependencies),
        ("Checking database", check_database),
        ("Creating environment template", create_environment_file),
    ]
    
    success_count = 0
    for step_name, step_func in steps:
        print(f"\n🔄 {step_name}...")
        if step_func():
            success_count += 1
        else:
            print(f"❌ Setup step failed: {step_name}")
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 SETUP SUMMARY")
    print("=" * 50)
    print(f"✅ Completed steps: {success_count}/{len(steps)}")
    
    if success_count == len(steps):
        print("\n🎉 Setup completed successfully!")
        print("\n🚀 Next steps:")
        print("   1. Review and update .env.template if needed")
        print("   2. Run the application: python app.py")
        print("   3. Open browser to: http://localhost:5004")
        print("   4. Login with username: admin, password: admin")
        print("\n⚠️  Remember to change the default password in production!")
    else:
        print("\n❌ Setup incomplete. Please resolve the issues above and try again.")
        print("\n💡 Manual installation steps:")
        print("   1. Install Python 3.9+")
        print("   2. pip install -r requirements.txt")
        print("   3. python init_db.py (if database missing)")
        print("   4. python app.py")

if __name__ == "__main__":
    main()
