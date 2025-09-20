"""Authentication and user management service layer."""
from datetime import datetime, timedelta
import secrets
import string

from helpers import get_db
from services.security import generate_password_hash, check_password_hash

RESET_TOKEN_TTL_HOURS = 24


def _now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def fetch_user_by_id(user_id):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()


def fetch_user_by_username(username):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()


def fetch_user_by_email(email):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()


def authenticate_user(username, password):
    user = fetch_user_by_username(username)
    if user and check_password_hash(user['password_hash'], password):
        return user
    return None


def update_last_login(user_id):
    db = get_db()
    db.execute('UPDATE users SET last_login = ? WHERE id = ?', (_now_str(), user_id))
    db.commit()


def is_username_taken(username, exclude_user_id=None):
    db = get_db()
    if exclude_user_id:
        row = db.execute(
            'SELECT 1 FROM users WHERE username = ? AND id != ?',
            (username, exclude_user_id)
        ).fetchone()
    else:
        row = db.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone()
    return row is not None


def is_email_taken(email, exclude_user_id=None):
    db = get_db()
    if exclude_user_id:
        row = db.execute(
            'SELECT 1 FROM users WHERE email = ? AND id != ?',
            (email, exclude_user_id)
        ).fetchone()
    else:
        row = db.execute('SELECT 1 FROM users WHERE email = ?', (email,)).fetchone()
    return row is not None


def create_user(username, password, email, full_name, role='viewer'):
    db = get_db()
    db.execute(
        'INSERT INTO users (username, password_hash, email, full_name, role) VALUES (?, ?, ?, ?, ?)',
        (username, generate_password_hash(password), email, full_name, role)
    )
    db.commit()


def update_user_profile(user_id, email, full_name):
    db = get_db()
    db.execute(
        'UPDATE users SET email = ?, full_name = ? WHERE id = ?',
        (email, full_name, user_id)
    )
    db.commit()


def change_user_password(user_id, password):
    db = get_db()
    db.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        (generate_password_hash(password), user_id)
    )
    db.commit()


def fetch_all_users():
    db = get_db()
    return db.execute('SELECT * FROM users ORDER BY username').fetchall()


def update_user_account(user_id, *, username, email, full_name, role, new_password=None):
    db = get_db()
    if new_password:
        db.execute(
            'UPDATE users SET username = ?, email = ?, full_name = ?, role = ?, password_hash = ? WHERE id = ?',
            (username, email, full_name, role, generate_password_hash(new_password), user_id)
        )
    else:
        db.execute(
            'UPDATE users SET username = ?, email = ?, full_name = ?, role = ? WHERE id = ?',
            (username, email, full_name, role, user_id)
        )
    db.commit()


def delete_user(user_id):
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()


def create_password_reset_token(user_id):
    token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    expires_at = (datetime.now() + timedelta(hours=RESET_TOKEN_TTL_HOURS)).strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    db.execute(
        'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
        (user_id, token, expires_at)
    )
    db.commit()
    return token


def fetch_valid_reset_token(token):
    db = get_db()
    return db.execute(
        'SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > ? AND used = 0',
        (token, _now_str())
    ).fetchone()


def mark_reset_token_used(token_id):
    db = get_db()
    db.execute('UPDATE password_reset_tokens SET used = 1 WHERE id = ?', (token_id,))
    db.commit()
