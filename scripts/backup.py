#!/usr/bin/env python3
"""
QCS Event Management Application - Backup Script
Create backups of the database and application files
"""

import os
import shutil
import sqlite3
import json
from datetime import datetime
from pathlib import Path

def create_database_backup():
    """Create a backup of the SQLite database"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = Path('backups')
    backup_dir.mkdir(exist_ok=True)
    
    if os.path.exists('database.db'):
        backup_file = backup_dir / f'database_backup_{timestamp}.db'
        shutil.copy2('database.db', backup_file)
        
        # Create database info file
        info_file = backup_dir / f'database_info_{timestamp}.json'
        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            
            # Get table information
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            # Count records in each table
            table_counts = {}
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                table_counts[table] = cursor.fetchone()[0]
            
            conn.close()
            
            backup_info = {
                'timestamp': timestamp,
                'database_file': str(backup_file),
                'tables': len(tables),
                'table_counts': table_counts,
                'total_records': sum(table_counts.values())
            }
            
            with open(info_file, 'w') as f:
                json.dump(backup_info, f, indent=2)
                
            print(f"✅ Database backed up to: {backup_file}")
            print(f"📊 Backup info saved to: {info_file}")
            return True
            
        except sqlite3.Error as e:
            print(f"❌ Database backup failed: {e}")
            return False
    else:
        print("⚠️  Database file not found")
        return False

def create_application_backup():
    """Create a full application backup"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = Path('backups')
    backup_dir.mkdir(exist_ok=True)
    
    app_backup_dir = backup_dir / f'app_backup_{timestamp}'
    
    try:
        # Files and directories to backup
        items_to_backup = [
            'app.py',
            'helpers.py',
            'config.py',
            'schema.sql',
            'init_db.py',
            'requirements.txt',
            'README.md',
            'CHANGELOG.md',
            'blueprints',
            'templates',
            'static',
            'docs'
        ]
        
        app_backup_dir.mkdir(exist_ok=True)
        
        for item in items_to_backup:
            if os.path.exists(item):
                if os.path.isfile(item):
                    shutil.copy2(item, app_backup_dir)
                elif os.path.isdir(item):
                    shutil.copytree(item, app_backup_dir / item, dirs_exist_ok=True)
        
        # Create backup manifest
        manifest = {
            'timestamp': timestamp,
            'backup_type': 'application',
            'items_backed_up': items_to_backup,
            'backup_location': str(app_backup_dir)
        }
        
        manifest_file = app_backup_dir / 'backup_manifest.json'
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        print(f"✅ Application backed up to: {app_backup_dir}")
        return True
        
    except Exception as e:
        print(f"❌ Application backup failed: {e}")
        return False

def create_full_backup():
    """Create both database and application backups"""
    print("🔄 Creating full backup...")
    
    db_success = create_database_backup()
    app_success = create_application_backup()
    
    if db_success and app_success:
        print("✅ Full backup completed successfully")
        return True
    else:
        print("❌ Backup completed with errors")
        return False

def list_backups():
    """List all available backups"""
    backup_dir = Path('backups')
    
    if not backup_dir.exists():
        print("📁 No backups directory found")
        return
    
    db_backups = list(backup_dir.glob('database_backup_*.db'))
    app_backups = list(backup_dir.glob('app_backup_*'))
    
    print(f"\n📋 Available Backups:")
    print(f"Database backups: {len(db_backups)}")
    for backup in sorted(db_backups):
        size = backup.stat().st_size / 1024  # Size in KB
        print(f"  • {backup.name} ({size:.1f} KB)")
    
    print(f"\nApplication backups: {len(app_backups)}")
    for backup in sorted(app_backups):
        print(f"  • {backup.name}")

def cleanup_old_backups(keep_days=30):
    """Remove backups older than specified days"""
    backup_dir = Path('backups')
    
    if not backup_dir.exists():
        return
    
    import time
    cutoff_time = time.time() - (keep_days * 24 * 60 * 60)
    
    removed_count = 0
    for backup_file in backup_dir.iterdir():
        if backup_file.stat().st_mtime < cutoff_time:
            if backup_file.is_file():
                backup_file.unlink()
                removed_count += 1
            elif backup_file.is_dir():
                shutil.rmtree(backup_file)
                removed_count += 1
    
    if removed_count > 0:
        print(f"🧹 Cleaned up {removed_count} old backups (older than {keep_days} days)")
    else:
        print(f"✅ No old backups to clean up")

def main():
    """Main backup function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='QCS Event Management Backup Tool')
    parser.add_argument('--type', choices=['database', 'app', 'full'], default='full',
                       help='Type of backup to create')
    parser.add_argument('--list', action='store_true',
                       help='List available backups')
    parser.add_argument('--cleanup', type=int, metavar='DAYS', default=0,
                       help='Clean up backups older than DAYS')
    
    args = parser.parse_args()
    
    print("🔄 QCS Event Management Backup Tool")
    print("=" * 40)
    
    if args.list:
        list_backups()
        return
    
    if args.cleanup > 0:
        cleanup_old_backups(args.cleanup)
        return
    
    # Create backups
    if args.type == 'database':
        create_database_backup()
    elif args.type == 'app':
        create_application_backup()
    elif args.type == 'full':
        create_full_backup()
    
    print("\n💡 Backup Tips:")
    print("  • Run backups regularly (daily/weekly)")
    print("  • Store backups in a separate location")
    print("  • Test backup restoration periodically")
    print("  • Use --cleanup option to manage backup storage")

if __name__ == "__main__":
    main()
