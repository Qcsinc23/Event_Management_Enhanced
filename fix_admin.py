import sqlite3
import os
import sys
from app import generate_password_hash

def fix_admin():
    """Create or reset the admin user in the database"""
    print("Creating/resetting admin user...")
    
    # Connect to the database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Check if admin user exists
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    admin = cursor.fetchone()
    
    # Generate password hash
    password_hash = generate_password_hash('admin')
    
    if admin:
        # Update existing admin user
        cursor.execute(
            "UPDATE users SET password_hash = ?, email = 'admin@qcsevents.com', full_name = 'Administrator', role = 'admin' WHERE username = 'admin'",
            (password_hash,)
        )
        print("Admin user updated successfully!")
    else:
        # Create new admin user
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, full_name, role) VALUES (?, ?, ?, ?, ?)",
            ('admin', password_hash, 'admin@qcsevents.com', 'Administrator', 'admin')
        )
        print("Admin user created successfully!")
    
    # Commit changes and close connection
    conn.commit()
    conn.close()

if __name__ == "__main__":
    fix_admin()