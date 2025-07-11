#!/usr/bin/env python3
"""
QCS Event Management Application - Run Script
Simple script to start the application with proper configuration
"""

import os
import sys
from pathlib import Path

def load_environment():
    """Load environment variables from .env file if it exists"""
    env_file = Path('.env')
    if env_file.exists():
        print("📄 Loading environment from .env file")
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()
    else:
        print("⚠️  No .env file found, using default settings")

def check_requirements():
    """Check if required files exist"""
    required_files = ['app.py', 'database.db']
    missing_files = []
    
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing required files: {', '.join(missing_files)}")
        print("💡 Try running: python scripts/setup.py")
        return False
    
    return True

def main():
    """Main run function"""
    print("🚀 Starting QCS Event Management Application")
    print("=" * 50)
    
    # Change to the application directory
    app_dir = Path(__file__).parent
    os.chdir(app_dir)
    
    # Load environment
    load_environment()
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Set default environment variables
    os.environ.setdefault('FLASK_APP', 'app.py')
    os.environ.setdefault('FLASK_ENV', 'development')
    os.environ.setdefault('HOST', '0.0.0.0')
    os.environ.setdefault('PORT', '5004')
    
    # Display startup information
    host = os.environ.get('HOST', '0.0.0.0')
    port = os.environ.get('PORT', '5004')
    debug = os.environ.get('FLASK_ENV', 'development') == 'development'
    
    print(f"🌐 Host: {host}")
    print(f"🔌 Port: {port}")
    print(f"🐛 Debug Mode: {debug}")
    print(f"🔑 Database: {'✅ Found' if os.path.exists('database.db') else '❌ Missing'}")
    
    if debug:
        print("\n⚠️  Running in development mode")
        print("   For production, set FLASK_ENV=production")
    
    print(f"\n🌍 Application will be available at: http://localhost:{port}")
    print("👤 Default login: admin / admin")
    print("\n🔄 Starting server...")
    print("-" * 50)
    
    # Import and run the Flask app
    try:
        from app import app
        app.run(
            host=host,
            port=int(port),
            debug=debug
        )
    except ImportError as e:
        print(f"❌ Failed to import application: {e}")
        print("💡 Make sure all dependencies are installed:")
        print("   pip install -r requirements.txt")
    except Exception as e:
        print(f"❌ Failed to start application: {e}")

if __name__ == "__main__":
    main()
