import os
import sqlite3
import secrets
import string
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, abort, send_file, jsonify, Response
from functools import wraps
from werkzeug.exceptions import Forbidden
import tempfile
from forms import (
    LoginForm,
    RegistrationForm,
    ForgotPasswordForm,
    ResetPasswordForm,
    ProfileForm,
    PasswordChangeForm,
    UserCreateForm,
    UserEditForm,
)
from flask_wtf import CSRFProtect

# Custom password hashing functions compatible with Python 3.9+
# These functions replicate Werkzeug's format but avoid the hmac.new() digestmod issue.
def generate_password_hash(password, method='pbkdf2:sha256', salt_length=16):
    """Generate a password hash using the same format as Werkzeug but compatible with Python 3.9+"""
    if not method.startswith('pbkdf2:'):
        # Fallback for other methods if needed, though pbkdf2 is standard
        # This requires importing the original werkzeug functions if you need full fallback
        # from werkzeug.security import generate_password_hash as werkzeug_generate_password_hash
        # return werkzeug_generate_password_hash(password, method, salt_length)
        raise ValueError("Unsupported hashing method for this custom function")


    iterations = 260000 # Default in Werkzeug
    hash_name = 'sha256' # Default hash name
    if ':' in method:
        method_parts = method.split(':')
        if len(method_parts) >= 2:
            hash_name = method_parts[1]
            if len(method_parts) >= 3:
                try:
                    iterations = int(method_parts[2])
                except ValueError:
                    pass # Use default iterations if conversion fails

    salt = secrets.token_hex(salt_length)
    pwdhash = hashlib.pbkdf2_hmac(
        hash_name,
        password.encode('utf-8'),
        bytes.fromhex(salt),
        iterations
    )
    pwdhash_b64 = base64.b64encode(pwdhash).decode('ascii')
    return f'pbkdf2:{hash_name}:{iterations}${salt}${pwdhash_b64}'

def check_password_hash(pwhash, password):
    """Check a password against a given salted and hashed password value compatible with Python 3.9+"""
    try:
        # Handle bcrypt hashes (format: $2b$rounds$salt+hash)
        if pwhash.startswith('$2b$') or pwhash.startswith('$2a$') or pwhash.startswith('$2y$'):
            try:
                import bcrypt
                return bcrypt.checkpw(password.encode('utf-8'), pwhash.encode('utf-8'))
            except ImportError:
                print("bcrypt not available, cannot verify bcrypt hash")
                return False
        
        # Handle pbkdf2 hashes (existing implementation)
        elif pwhash.startswith('pbkdf2:'):
            parts = pwhash.split('$', 2)
            if len(parts) != 3: return False
            method, salt, hashval = parts

            method_parts = method.split(':')
            if len(method_parts) < 2: return False
            hash_name = method_parts[1]
            iterations = 260000 # Default
            if len(method_parts) >= 3:
                try:
                    iterations = int(method_parts[2])
                except ValueError:
                    pass # Use default if conversion fails

            try:
                pwdhash_check = hashlib.pbkdf2_hmac(
                    hash_name,
                    password.encode('utf-8'),
                    bytes.fromhex(salt),
                    iterations
                )
                pwdhash_check_b64 = base64.b64encode(pwdhash_check).decode('ascii')
                return hmac.compare_digest(pwdhash_check_b64, hashval)
            except Exception as e:
                print(f"Password verification error during pbkdf2: {str(e)}")
                return False
        else:
            # Try Werkzeug's original implementation as fallback
            try:
                from werkzeug.security import check_password_hash as werkzeug_check
                return werkzeug_check(pwhash, password)
            except Exception:
                print(f"Unsupported password hash format: {pwhash[:20]}...")
                return False
    except Exception as e:
        print(f"General password check error: {str(e)}")
        return False

# Try to import WeasyPrint for PDF generation, but don't fail if not available
try:
    from weasyprint import HTML
    weasyprint_available = True
except (ImportError, OSError):
    weasyprint_available = False
    print("WeasyPrint not available. PDF generation will be disabled.")

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_please_change_in_production')
app.config['DATABASE'] = os.path.join(app.root_path, 'database.db')

csrf = CSRFProtect(app)


def flash_form_errors(form):
    """Flash all errors for a submitted form."""
    for field_name, errors in form.errors.items():
        label = getattr(form, field_name).label.text if hasattr(form, field_name) else field_name.replace('_', ' ').title()
        for error in errors:
            flash(f"{label}: {error}", 'danger')

# Security enhancements
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# CSRF protection enhancement
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token validity

# Import helper functions
from helpers import get_db, close_db, login_required, role_required, get_current_user

# Database initialization function (uses get_db)
def init_db():
    """Initialize the database with schema"""
    try:
        db = get_db()
        with app.app_context():
            with app.open_resource('schema.sql') as f:
                db.executescript(f.read().decode('utf8'))
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {e}")

@app.cli.command('init-db')
def init_db_command():
    """Command to initialize the database"""
    init_db()
    print('Database initialized')

# Register close_db with the application
app.teardown_appcontext(close_db)

# Routes (These use the imported helpers)
@app.route('/landing')
def landing():
    """Landing page for visitors"""
    return render_template('landing.html')

@app.route('/')
def index():
    """Home page / dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('landing'))

    db = get_db()
    # Get upcoming events
    upcoming_events = db.execute(
        'SELECT e.*, c.name as client_name, c.color as client_color '
        'FROM events e JOIN clients c ON e.client_id = c.id '
        'WHERE e.event_date >= ? '
        'ORDER BY e.event_date ASC LIMIT 5',
        (datetime.now().strftime('%Y-%m-%d'),)
    ).fetchall()

    # Get stats (count of events by status)
    event_stats = {
        'booked': db.execute('SELECT COUNT(*) FROM events WHERE status = ?', ('booked',)).fetchone()[0],
        'completed': db.execute('SELECT COUNT(*) FROM events WHERE status = ?', ('completed',)).fetchone()[0],
        'cancelled': db.execute('SELECT COUNT(*) FROM events WHERE status = ?', ('cancelled',)).fetchone()[0],
    }

    # Get inventory stats
    inventory_stats = {
        'total_elements': db.execute('SELECT COUNT(*) FROM elements').fetchone()[0],
        'total_kits': db.execute('SELECT COUNT(*) FROM kits').fetchone()[0],
        'total_equipment': db.execute('SELECT COUNT(*) FROM equipment').fetchone()[0],
    }

    # Get low stock alerts (elements with quantity less than 5)
    low_stock_elements = db.execute(
        '''SELECT e.*, t.type_name
           FROM elements e
           JOIN element_types t ON e.type_id = t.type_id
           WHERE e.quantity < 5
           ORDER BY e.quantity ASC
           LIMIT 5'''
    ).fetchall()

    # Combine event and inventory stats
    stats = {**event_stats, **inventory_stats}

    return render_template('index.html', upcoming_events=upcoming_events, stats=stats,
                          low_stock_elements=low_stock_elements)

# User management routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if not user or not check_password_hash(user['password_hash'], password):
            form.password.errors.append('Invalid username or password')
            flash_form_errors(form)
        else:
            db.execute(
                'UPDATE users SET last_login = ? WHERE id = ?',
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id'])
            )
            db.commit()

            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful', 'success')
            return redirect(url_for('index'))
    elif request.method == 'POST':
        flash_form_errors(form)

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip()
        full_name = form.full_name.data.strip()
        password = form.password.data

        db = get_db()
        username_exists = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        email_exists = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()

        if username_exists:
            form.username.errors.append(f'User {username} is already registered')
        if email_exists:
            form.email.errors.append(f'Email {email} is already registered')

        if form.errors:
            flash_form_errors(form)
        else:
            db.execute(
                'INSERT INTO users (username, password_hash, email, full_name, role) VALUES (?, ?, ?, ?, ?)',
                (username, generate_password_hash(password), email, full_name, 'viewer')
            )
            db.commit()
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))
    elif request.method == 'POST':
        flash_form_errors(form)

    return render_template('register.html', form=form)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle forgotten password requests"""
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.email.data.strip()

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user is None:
            flash('If your email is registered, you will receive password reset instructions.', 'info')
            return redirect(url_for('login'))

        token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        expires_at = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')

        db.execute(
            'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            (user['id'], token, expires_at)
        )
        db.commit()

        reset_url = url_for('reset_password', token=token, _external=True)
        flash(f'Password reset link (would be emailed in production): {reset_url}', 'info')

        return redirect(url_for('login'))
    elif request.method == 'POST':
        flash_form_errors(form)

    return render_template('forgot_password.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password using token"""
    db = get_db()

    # Check if token is valid
    token_data = db.execute(
        'SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > ? AND used = 0',
        (token, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    ).fetchone()

    if token_data is None:
        flash('Invalid or expired reset token. Please request a new one.', 'danger')
        return redirect(url_for('login'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        password = form.password.data

        db.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (generate_password_hash(password), token_data['user_id'])
        )
        db.execute(
            'UPDATE password_reset_tokens SET used = 1 WHERE id = ?',
            (token_data['id'],)
        )
        db.commit()

        flash('Password has been reset! You can now login with your new password.', 'success')
        return redirect(url_for('login'))
    elif request.method == 'POST':
        flash_form_errors(form)

    return render_template('reset_password.html', token=token, form=form)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management"""
    user = get_current_user()
    profile_form = ProfileForm(data={'full_name': user['full_name'], 'email': user['email']})
    password_form = PasswordChangeForm()
    db = get_db()

    if profile_form.submit_profile.data:
        if profile_form.validate():
            email = profile_form.email.data.strip()
            full_name = profile_form.full_name.data.strip()

            email_check = db.execute(
                'SELECT id FROM users WHERE email = ? AND id != ?',
                (email, user['id'])
            ).fetchone()

            if email_check:
                profile_form.email.errors.append('Email is already in use by another account')
                flash_form_errors(profile_form)
            else:
                db.execute(
                    'UPDATE users SET email = ?, full_name = ? WHERE id = ?',
                    (email, full_name, user['id'])
                )
                db.commit()
                flash('Profile updated successfully', 'success')
                return redirect(url_for('profile'))
        else:
            flash_form_errors(profile_form)

    elif password_form.submit_password.data:
        if password_form.validate():
            current_password = password_form.current_password.data
            new_password = password_form.new_password.data

            if not check_password_hash(user['password_hash'], current_password):
                password_form.current_password.errors.append('Current password is incorrect')
                flash_form_errors(password_form)
            else:
                db.execute(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    (generate_password_hash(new_password), user['id'])
                )
                db.commit()
                flash('Password updated successfully', 'success')
                return redirect(url_for('profile'))
        else:
            flash_form_errors(password_form)

    return render_template('profile.html', user=user, profile_form=profile_form, password_form=password_form)


@app.route('/users')
@login_required
@role_required('admin')
def users():
    """List all users (admin only)"""
    db = get_db()
    all_users = db.execute('SELECT * FROM users ORDER BY username').fetchall()
    return render_template('users.html', users=all_users)

@app.route('/users/new', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def new_user():
    """Create a new user (admin only)"""
    form = UserCreateForm()
    db = get_db()

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip()
        full_name = form.full_name.data.strip()
        role = form.role.data
        password = form.password.data

        username_exists = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        email_exists = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()

        if username_exists:
            form.username.errors.append(f'User {username} is already registered')
        if email_exists:
            form.email.errors.append(f'Email {email} is already registered')

        if form.errors:
            flash_form_errors(form)
        else:
            db.execute(
                'INSERT INTO users (username, password_hash, email, full_name, role) VALUES (?, ?, ?, ?, ?)',
                (username, generate_password_hash(password), email, full_name, role)
            )
            db.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('users'))
    elif request.method == 'POST':
        flash_form_errors(form)

    return render_template('new_user.html', form=form)


@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    """Edit a user (admin only)"""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if user is None:
        abort(404)

    form = UserEditForm(data={
        'username': user['username'],
        'email': user['email'],
        'full_name': user['full_name'],
        'role': user['role'],
    })

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip()
        full_name = form.full_name.data.strip()
        role = form.role.data
        new_password = form.new_password.data

        username_check = db.execute(
            'SELECT id FROM users WHERE username = ? AND id != ?',
            (username, user_id)
        ).fetchone()
        email_check = db.execute(
            'SELECT id FROM users WHERE email = ? AND id != ?',
            (email, user_id)
        ).fetchone()

        if username_check:
            form.username.errors.append('Username is already in use by another account')
        if email_check:
            form.email.errors.append('Email is already in use by another account')
        if new_password and not form.confirm_password.data:
            form.confirm_password.errors.append('Please confirm the new password')

        if form.errors:
            flash_form_errors(form)
        else:
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
            flash('User updated successfully', 'success')
            return redirect(url_for('users'))
    elif request.method == 'POST':
        form.validate()
        flash_form_errors(form)

    return render_template('edit_user.html', user=user, form=form)


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    """Delete a user (admin only)"""
    # Don't allow deleting yourself
    if user_id == session['user_id']:
        flash('You cannot delete your own account.', 'danger') # Simplified message
        return redirect(url_for('users'))

    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('users'))

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('landing'))

# Client Management Routes
@app.route('/clients')
@login_required
def clients():
    """List all clients"""
    db = get_db()

    # Get search parameters
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'name')

    # Build query
    query = """
        SELECT c.*,
               COUNT(e.event_id) as event_count
        FROM clients c
        LEFT JOIN events e ON c.id = e.client_id
    """

    # Add search condition if provided
    params = []
    if search:
        query += " WHERE c.name LIKE ? OR c.contact_person LIKE ? OR c.email LIKE ? OR c.phone LIKE ?"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param, search_param])

    # Add grouping
    query += " GROUP BY c.id" # Corrected grouping

    # Add sorting
    if sort == 'name':
        query += " ORDER BY c.name ASC"
    elif sort == 'name_desc':
        query += " ORDER BY c.name DESC"
    elif sort == 'created':
        query += " ORDER BY c.created_at DESC"
    elif sort == 'created_desc': # Should be ASC for oldest first
        query += " ORDER BY c.created_at ASC"
    else:
        query += " ORDER BY c.name ASC"  # Default to name ascending

    clients = db.execute(query, params).fetchall()

    return render_template('clients.html', clients=clients)

@app.route('/clients/new', methods=['GET', 'POST'])
@login_required
def new_client():
    """Create a new client"""
    if request.method == 'POST':
        name = request.form['name']
        color = request.form['color']
        contact_person = request.form.get('contact_person', '')
        email = request.form.get('email', '')
        phone = request.form.get('phone', '')
        address = request.form.get('address', '')
        city = request.form.get('city', '')
        state = request.form.get('state', '')
        zip_code = request.form.get('zip', '')
        preferences = request.form.get('preferences', '')
        notes = request.form.get('notes', '')

        error = None
        if not name:
            error = 'Client name is required'
        elif not color:
            error = 'Color is required'

        if error is not None:
            flash(error, 'danger')
        else:
            db = get_db()
            db.execute(
                '''INSERT INTO clients
                   (name, color, contact_person, email, phone, address, city, state, zip,
                    preferences, notes, created_at, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (name, color, contact_person, email, phone, address, city, state, zip_code,
                 preferences, notes, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), session.get('user_id'))
            )
            db.commit()
            flash('Client created successfully', 'success')
            return redirect(url_for('clients'))

    return render_template('new_client.html')

@app.route('/clients/<int:client_id>')
@login_required
def view_client(client_id):
    """View client details"""
    db = get_db()
    client = db.execute('SELECT * FROM clients WHERE id = ?', (client_id,)).fetchone()

    if client is None:
        abort(404)

    # Get client communications
    communications = db.execute(
        '''SELECT c.*, u.username as user_name
           FROM client_communications c
           JOIN users u ON c.user_id = u.id
           WHERE c.client_id = ?
           ORDER BY c.date DESC''',
        (client_id,)
    ).fetchall()

    # Get client events
    events = db.execute(
        'SELECT * FROM events WHERE client_id = ? ORDER BY event_date DESC',
        (client_id,)
    ).fetchall()

    # Get client invoices
    invoices = db.execute(
        '''SELECT i.*, e.event_name as event_title
           FROM invoices i
           JOIN events e ON i.event_id = e.event_id
           WHERE i.client_id = ?
           ORDER BY i.issue_date DESC''',
        (client_id,)
    ).fetchall()

    # Calculate stats
    stats = {
        'total_events': len(events),
        'upcoming_events': db.execute(
            'SELECT COUNT(*) FROM events WHERE client_id = ? AND event_date >= ? AND status != ?',
            (client_id, datetime.now().strftime('%Y-%m-%d'), 'cancelled')
        ).fetchone()[0],
        'total_revenue': db.execute(
            'SELECT COALESCE(SUM(amount), 0) FROM invoices WHERE client_id = ? AND status = ?',
            (client_id, 'paid')
        ).fetchone()[0]
    }

    # Get today's date for the communication form
    today = datetime.now().strftime('%Y-%m-%d')

    return render_template('view_client.html', client=client, communications=communications,
                           events=events, invoices=invoices, stats=stats, today=today)

@app.route('/clients/<int:client_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_client(client_id):
    """Edit a client"""
    db = get_db()
    client = db.execute('SELECT * FROM clients WHERE id = ?', (client_id,)).fetchone()

    if client is None:
        abort(404)

    if request.method == 'POST':
        name = request.form['name']
        color = request.form['color']
        contact_person = request.form.get('contact_person', '')
        email = request.form.get('email', '')
        phone = request.form.get('phone', '')
        address = request.form.get('address', '')
        city = request.form.get('city', '')
        state = request.form.get('state', '')
        zip_code = request.form.get('zip', '')
        preferences = request.form.get('preferences', '')
        notes = request.form.get('notes', '')

        error = None
        if not name:
            error = 'Client name is required'
        elif not color:
            error = 'Color is required'

        if error is not None:
            flash(error, 'danger')
        else:
            db.execute(
                '''UPDATE clients SET
                   name = ?, color = ?, contact_person = ?, email = ?, phone = ?,
                   address = ?, city = ?, state = ?, zip = ?, preferences = ?, notes = ?
                   WHERE id = ?''',
                (name, color, contact_person, email, phone, address, city, state,
                 zip_code, preferences, notes, client_id) # Removed trailing comma
            )
            db.commit()
            flash('Client updated successfully', 'success')
            return redirect(url_for('view_client', client_id=client_id))

    return render_template('edit_client.html', client=client)

@app.route('/clients/<int:client_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_client(client_id):
    """Delete a client"""
    # Removed incorrect check: if user_id == session['user_id']:

    db = get_db()

    # Check if client has associated events or invoices before deleting
    event_count = db.execute('SELECT COUNT(*) FROM events WHERE client_id = ?', (client_id,)).fetchone()[0]
    invoice_count = db.execute('SELECT COUNT(*) FROM invoices WHERE client_id = ?', (client_id,)).fetchone()[0]

    if event_count > 0 or invoice_count > 0:
         flash('Cannot delete client with associated events or invoices. Please reassign or delete them first.', 'danger')
         return redirect(url_for('clients'))


    # Delete related records first to maintain referential integrity
    db.execute('DELETE FROM client_communications WHERE client_id = ?', (client_id,))

    # No need to delete events/invoices here due to the check above,
    # but if cascading delete was desired, it would happen here.

    # Finally delete the client
    db.execute('DELETE FROM clients WHERE id = ?', (client_id,))
    db.commit()

    flash('Client deleted successfully', 'success') # Corrected message
    return redirect(url_for('clients'))


@app.route('/clients/<int:client_id>/communications/add', methods=['POST'])
@login_required
def add_communication(client_id):
    """Add a communication record for a client"""
    db = get_db()
    client = db.execute('SELECT id FROM clients WHERE id = ?', (client_id,)).fetchone()

    if client is None:
        abort(404)

    comm_type = request.form['type']
    date = request.form['date']
    notes = request.form['notes']

    error = None
    if not comm_type:
        error = 'Communication type is required'
    elif not date:
        error = 'Date is required'
    elif not notes:
        error = 'Notes are required'

    if error is not None:
        flash(error, 'danger')
    else:
        db.execute(
            'INSERT INTO client_communications (client_id, user_id, date, type, notes) VALUES (?, ?, ?, ?, ?)',
            (client_id, session['user_id'], date, comm_type, notes)
        )
        db.commit()
        flash('Communication record added successfully', 'success')

    return redirect(url_for('view_client', client_id=client_id) + '#communications')

# Calendar routes now handled by calendar_bp (Placeholder comment)

# Event Categories Management
@app.route('/categories')
@login_required
def categories():
    """List all event categories"""
    db = get_db()
    categories = db.execute('SELECT * FROM event_categories ORDER BY name').fetchall()
    return render_template('categories.html', categories=categories)

@app.route('/categories/new', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def new_category():
    """Create a new event category"""
    if request.method == 'POST':
        name = request.form['name']
        color = request.form['color']
        description = request.form.get('description', '')

        error = None
        if not name:
            error = 'Category name is required'
        elif not color:
            error = 'Color is required'

        db = get_db()
        if db.execute('SELECT id FROM event_categories WHERE name = ?', (name,)).fetchone():
            error = f'Category "{name}" already exists'

        if error is not None:
            flash(error, 'danger')
        else:
            db.execute(
                'INSERT INTO event_categories (name, color, description) VALUES (?, ?, ?)',
                (name, color, description)
            )
            db.commit()
            flash('Category created successfully', 'success')
            return redirect(url_for('categories'))

    return render_template('new_category.html')

@app.route('/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def edit_category(category_id):
    """Edit an event category"""
    db = get_db()
    category = db.execute('SELECT * FROM event_categories WHERE id = ?', (category_id,)).fetchone()

    if category is None:
        abort(404)

    if request.method == 'POST':
        name = request.form['name']
        color = request.form['color']
        description = request.form.get('description', '')

        error = None
        if not name:
            error = 'Category name is required'
        elif not color:
            error = 'Color is required'

        # Check if another category with this name exists
        existing = db.execute(
            'SELECT id FROM event_categories WHERE name = ? AND id != ?',
            (name, category_id)
        ).fetchone()

        if existing:
            error = f'Category "{name}" already exists'

        if error is not None:
            flash(error, 'danger')
        else:
            db.execute(
                '''UPDATE event_categories SET name = ?, color = ?, description = ? WHERE id = ?''',
                (name, color, description, category_id)
            )
            db.commit()
            flash('Category updated successfully', 'success')
            return redirect(url_for('categories'))

    return render_template('edit_category.html', category=category)

@app.route('/categories/<int:category_id>/delete', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def delete_category(category_id):
    """Delete an event category"""
    db = get_db()

    # Update any events using this category to have no category
    db.execute('UPDATE events SET category_id = NULL WHERE category_id = ?', (category_id,))

    # Delete the category
    db.execute('DELETE FROM event_categories WHERE id = ?', (category_id,))
    db.commit()

    flash('Category deleted successfully', 'success')
    return redirect(url_for('categories'))

# Equipment Management
@app.route('/equipment')
@login_required
def equipment():
    """List all equipment items"""
    db = get_db()
    equipment = db.execute(
        '''SELECT e.*,
           (SELECT COUNT(*) FROM equipment_assignments WHERE equipment_id = e.id) as assignment_count
           FROM equipment e ORDER BY e.name'''
    ).fetchall()
    return render_template('equipment.html', equipment=equipment)

@app.route('/equipment/new', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def new_equipment():
    """Add new equipment item"""
    if request.method == 'POST':
        name = request.form['name']
        quantity = request.form['quantity']
        description = request.form.get('description', '')
        notes = request.form.get('notes', '')

        error = None
        if not name:
            error = 'Equipment name is required'
        elif not quantity or not quantity.isdigit() or int(quantity) < 1:
            error = 'Quantity must be a positive number'

        if error is not None:
            flash(error, 'danger')
        else:
            db = get_db()
            db.execute(
                'INSERT INTO equipment (name, quantity, description, notes) VALUES (?, ?, ?, ?)',
                (name, int(quantity), description, notes) # Ensure quantity is int
            )
            db.commit()
            flash('Equipment added successfully', 'success')
            return redirect(url_for('equipment'))

    return render_template('new_equipment.html')

@app.route('/equipment/<int:equipment_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def edit_equipment(equipment_id):
    """Edit equipment item"""
    db = get_db()
    equipment_item = db.execute('SELECT * FROM equipment WHERE id = ?', (equipment_id,)).fetchone()

    if equipment_item is None:
        abort(404)

    # Get current assignments count for validation
    assignments_count = db.execute(
        'SELECT COUNT(*) FROM equipment_assignments WHERE equipment_id = ?',
        (equipment_id,)
    ).fetchone()[0]

    if request.method == 'POST':
        name = request.form['name']
        quantity_str = request.form['quantity']
        description = request.form.get('description', '')
        notes = request.form.get('notes', '')

        error = None
        quantity = 0
        if not name:
            error = 'Equipment name is required'
        elif not quantity_str or not quantity_str.isdigit():
             error = 'Quantity must be a valid number'
        else:
            quantity = int(quantity_str)
            if quantity < 1:
                error = 'Quantity must be a positive number'
            elif quantity < assignments_count:
                error = f'Cannot reduce quantity below current assignments ({assignments_count})'

        if error is not None:
            flash(error, 'danger')
        else:
            db.execute(
                'UPDATE equipment SET name = ?, quantity = ?, description = ?, notes = ? WHERE id = ?',
                (name, quantity, description, notes, equipment_id)
            )
            db.commit()
            flash('Equipment updated successfully', 'success')
            return redirect(url_for('equipment'))

    return render_template('edit_equipment.html', equipment=equipment_item, assignments_count=assignments_count)

@app.route('/equipment/<int:equipment_id>/delete', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def delete_equipment(equipment_id):
    """Delete equipment item"""
    db = get_db()

    # Check if this equipment is currently assigned
    assignments = db.execute(
        'SELECT COUNT(*) FROM equipment_assignments WHERE equipment_id = ?',
        (equipment_id,)
    ).fetchone()[0]

    if assignments > 0:
        flash('Cannot delete equipment that is currently assigned to events. Please remove the assignments first.', 'danger')
        return redirect(url_for('equipment'))

    # Delete the equipment
    db.execute('DELETE FROM equipment WHERE id = ?', (equipment_id,))
    db.commit()

    flash('Equipment deleted successfully', 'success')
    return redirect(url_for('equipment'))

# Event Templates
@app.route('/templates')
@login_required
def templates():
    """List all event templates"""
    db = get_db()
    templates_data = db.execute(
        '''SELECT t.*, c.name as category_name, c.color as category_color
           FROM event_templates t
           LEFT JOIN event_categories c ON t.category_id = c.id
           ORDER BY t.name'''
    ).fetchall()

    # Convert to list of dicts to add equipment count
    templates = []
    for t in templates_data:
        template = dict(t)

        # Count equipment items for this template
        equipment_count = db.execute(
            'SELECT COUNT(*) FROM template_equipment WHERE template_id = ?',
            (template['id'],)
        ).fetchone()[0]
        template['equipment_count'] = equipment_count

        # Count events using this template
        events_count = db.execute(
            'SELECT COUNT(*) FROM events WHERE template_id = ?',
            (template['id'],)
        ).fetchone()[0]
        template['events_count'] = events_count

        templates.append(template)

    return render_template('templates.html', templates=templates)

@app.route('/templates/new', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def new_template():
    """Create a new event template"""
    db = get_db()

    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        category_id = request.form.get('category_id') or None
        color = request.form.get('color', '#3788d8')
        default_duration = request.form.get('default_duration', '2')
        notes = request.form.get('notes', '')

        # Get equipment selections
        equipment_ids = request.form.getlist('equipment_ids')
        equipment_qtys = {}
        for eq_id in equipment_ids:
            qty_key = f'equipment_qty_{eq_id}' # Corrected key format
            if qty_key in request.form:
                try:
                    qty = int(request.form[qty_key])
                    if qty > 0:
                        equipment_qtys[eq_id] = qty
                except ValueError:
                    pass

        error = None
        if not name:
            error = 'Template name is required'

        if error is not None:
            flash(error, 'danger')
        else:
            # Create the template
            cursor = db.execute(
                '''INSERT INTO event_templates
                   (name, description, category_id, color, default_duration, notes)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (name, description, category_id, color, default_duration, notes)
            )
            template_id = cursor.lastrowid

            # Add equipment assignments
            for eq_id, qty in equipment_qtys.items():
                db.execute(
                    '''INSERT INTO template_equipment
                       (template_id, equipment_id, quantity)
                       VALUES (?, ?, ?)''',
                    (template_id, eq_id, qty)
                )

            db.commit()
            flash('Template created successfully', 'success')
            return redirect(url_for('templates'))

    # Get categories and equipment for the form
    categories = db.execute('SELECT * FROM event_categories ORDER BY name').fetchall()
    equipment_list = db.execute('SELECT * FROM equipment ORDER BY name').fetchall()

    return render_template('new_template.html', categories=categories, equipment_list=equipment_list)

@app.route('/templates/<int:template_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def edit_template(template_id):
    """Edit an event template"""
    db = get_db()
    template = db.execute('SELECT * FROM event_templates WHERE id = ?', (template_id,)).fetchone()

    if template is None:
        abort(404)

    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        category_id = request.form.get('category_id') or None
        color = request.form.get('color', '#3788d8')
        default_duration = request.form.get('default_duration', '2')
        notes = request.form.get('notes', '')

        # Get equipment selections
        equipment_ids = request.form.getlist('equipment_ids')
        equipment_qtys = {}
        for eq_id in equipment_ids:
            qty_key = f'equipment_qty_{eq_id}' # Corrected key format
            if qty_key in request.form:
                try:
                    qty = int(request.form[qty_key])
                    if qty > 0:
                        equipment_qtys[eq_id] = qty
                except ValueError:
                    pass

        error = None
        if not name:
            error = 'Template name is required'

        if error is not None:
            flash(error, 'danger')
        else:
            # Update the template
            db.execute(
                '''UPDATE event_templates SET
                   name = ?, description = ?, category_id = ?,
                   color = ?, default_duration = ?, notes = ?
                   WHERE id = ?''',
                (name, description, category_id, color, default_duration, notes, template_id)
            )

            # Remove existing equipment assignments
            db.execute('DELETE FROM template_equipment WHERE template_id = ?', (template_id,))

            # Add new equipment assignments
            for eq_id, qty in equipment_qtys.items():
                db.execute(
                    '''INSERT INTO template_equipment
                       (template_id, equipment_id, quantity)
                       VALUES (?, ?, ?)''',
                    (template_id, eq_id, qty)
                )

            db.commit()
            flash('Template updated successfully', 'success')
            return redirect(url_for('templates'))

    # Get categories and equipment for the form
    categories = db.execute('SELECT * FROM event_categories ORDER BY name').fetchall()
    equipment_list = db.execute('SELECT * FROM equipment ORDER BY name').fetchall()

    # Get current equipment assignments
    template_equipment_data = db.execute(
        '''SELECT te.*, e.name, e.quantity as available_qty
           FROM template_equipment te
           JOIN equipment e ON te.equipment_id = e.id
           WHERE te.template_id = ?''',
        (template_id,)
    ).fetchall()
    # Convert to dict for easier access in template
    template_equipment = {item['equipment_id']: item['quantity'] for item in template_equipment_data}


    return render_template(
        'edit_template.html',
        template=template,
        categories=categories,
        equipment_list=equipment_list,
        template_equipment=template_equipment # Pass the dict
    )


@app.route('/templates/<int:template_id>/delete', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def delete_template(template_id):
    """Delete an event template"""
    db = get_db()

    # Check if template is used by any events
    event_count = db.execute('SELECT COUNT(*) FROM events WHERE template_id = ?', (template_id,)).fetchone()[0]
    if event_count > 0:
        flash(f'Cannot delete template used by {event_count} events. Please update events first.', 'danger')
        return redirect(url_for('templates'))

    # Remove equipment assignments
    db.execute('DELETE FROM template_equipment WHERE template_id = ?', (template_id,))

    # Delete the template
    db.execute('DELETE FROM event_templates WHERE id = ?', (template_id,))
    db.commit()

    flash('Template deleted successfully', 'success')
    return redirect(url_for('templates'))

# All event/calendar routes have been moved to blueprints:
# - Calendar/Events routes -> calendar_bp
# - Location routes -> locations_bp
# - Task routes -> tasks_bp
# Only keeping core app routes and the populate-db utility route

# Element Types Management Routes
@app.route('/element-types')
@login_required
def element_types():
    """List all element types"""
    db = get_db()

    # Get all element types with count of elements for each
    types = db.execute(
        '''SELECT t.*, COUNT(e.element_id) as element_count
           FROM element_types t
           LEFT JOIN elements e ON t.type_id = e.type_id -- Corrected join condition
           GROUP BY t.type_id
           ORDER BY t.type_name'''
    ).fetchall()

    return render_template('element_types.html', types=types)

@app.route('/element-types/new', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def new_element_type():
    """Create a new element type"""
    if request.method == 'POST':
        type_name = request.form['type_name']

        error = None
        if not type_name:
            error = 'Type name is required'

        db = get_db()
        if db.execute('SELECT type_id FROM element_types WHERE type_name = ?',
                     (type_name,)).fetchone():
            error = f'Type "{type_name}" already exists'

        if error is not None:
            flash(error, 'danger')
        else:
            db.execute('INSERT INTO element_types (type_name) VALUES (?)', (type_name,))
            db.commit()
            flash('Element type created successfully', 'success')
            return redirect(url_for('element_types'))

    return render_template('new_element_type.html')

@app.route('/element-types/<int:type_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def edit_element_type(type_id):
    """Edit an element type"""
    db = get_db()
    element_type = db.execute('SELECT * FROM element_types WHERE type_id = ?', (type_id,)).fetchone()

    if element_type is None:
        abort(404)

    if request.method == 'POST':
        type_name = request.form['type_name']

        error = None
        if not type_name:
            error = 'Type name is required'

        # Check if another type with this name exists
        existing = db.execute(
            'SELECT type_id FROM element_types WHERE type_name = ? AND type_id != ?',
            (type_name, type_id)
        ).fetchone()

        if existing:
            error = f'Type "{type_name}" already exists'

        if error is not None:
            flash(error, 'danger')
        else:
            db.execute(
                'UPDATE element_types SET type_name = ? WHERE type_id = ?',
                (type_name, type_id)
            )
            db.commit()
            flash('Element type updated successfully', 'success')
            return redirect(url_for('element_types'))

    return render_template('edit_element_type.html', type=element_type)

@app.route('/element-types/<int:type_id>/delete', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def delete_element_type(type_id):
    """Delete an element type"""
    db = get_db()

    # Check if this type is used by any elements
    element_count = db.execute('SELECT COUNT(*) FROM elements WHERE type_id = ?', (type_id,)).fetchone()[0]

    if element_count > 0:
        flash(f'Cannot delete this type because it is used by {element_count} elements', 'danger')
        return redirect(url_for('element_types'))

    db.execute('DELETE FROM element_types WHERE type_id = ?', (type_id,))
    db.commit()

    flash('Element type deleted successfully', 'success')
    return redirect(url_for('element_types'))

# Elements Management Routes
@app.route('/elements')
@login_required
def elements():
    """List all elements"""
    db = get_db()

    # Get search parameters
    search = request.args.get('search', '')
    type_filter = request.args.get('type', '')
    location_filter = request.args.get('location', '') # Assuming location_id exists in elements table

    # Base query
    query = '''
        SELECT e.*, t.type_name
        FROM elements e
        JOIN element_types t ON e.type_id = t.type_id
        WHERE 1=1
    '''

    # Parameters for the query
    params = []

    # Add search condition if provided
    if search:
        # Complete the unterminated string literal and add LIKE for item_number
        query += " AND (e.item_description LIKE ? OR e.item_number LIKE ?)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param])

    # Add type filter if provided
    if type_filter:
        query += " AND e.type_id = ?"
        params.append(type_filter)

    # Add location filter if provided (assuming location_id column exists)
    # if location_filter:
    #     query += " AND e.location_id = ?"
    #     params.append(location_filter)

    # Add ordering
    query += " ORDER BY e.item_description ASC"

    elements_list = db.execute(query, params).fetchall()

    # Get element types and locations for filters
    element_types_list = db.execute('SELECT * FROM element_types ORDER BY type_name').fetchall()
    # locations_list = db.execute('SELECT * FROM locations ORDER BY name').fetchall() # Assuming locations table

    return render_template('elements.html',
                           elements=elements_list,
                           types=element_types_list,
                           # locations=locations_list,
                           search=search,
                           type_filter=type_filter,
                           location_filter=location_filter)


# --- Add remaining Element routes (new, edit, view, delete) ---
# These were missing from the provided snippets but are needed for full functionality

@app.route('/elements/new', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def new_element():
    """Create a new element"""
    db = get_db()
    if request.method == 'POST':
        item_number = request.form.get('item_number')
        item_description = request.form['item_description']
        type_id = request.form['type_id']
        quantity = request.form['quantity']
        unit_cost = request.form.get('unit_cost') or 0.0
        notes = request.form.get('notes', '')

        error = None
        if not item_description:
            error = 'Item description is required.'
        elif not type_id:
            error = 'Element type is required.'
        elif not quantity or not quantity.isdigit() or int(quantity) < 0:
             error = 'Quantity must be a non-negative number.'
        elif unit_cost:
             try:
                 unit_cost = float(unit_cost)
                 if unit_cost < 0: error = 'Unit cost cannot be negative.'
             except ValueError:
                 error = 'Unit cost must be a valid number.'

        if error:
            flash(error, 'danger')
        else:
            db.execute(
                '''INSERT INTO elements (item_number, item_description, type_id, quantity, unit_cost, notes)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (item_number, item_description, type_id, int(quantity), unit_cost, notes)
            )
            db.commit()
            flash('Element created successfully.', 'success')
            return redirect(url_for('elements'))

    element_types_list = db.execute('SELECT * FROM element_types ORDER BY type_name').fetchall()
    return render_template('new_element.html', types=element_types_list)


@app.route('/elements/<int:element_id>')
@login_required
def view_element(element_id):
    """View element details"""
    db = get_db()
    element = db.execute(
        '''SELECT e.*, t.type_name
           FROM elements e
           JOIN element_types t ON e.type_id = t.type_id
           WHERE e.element_id = ?''', (element_id,)
    ).fetchone()

    if element is None:
        abort(404)

    # Get kit associations
    kits = db.execute(
        '''SELECT k.kit_id, k.kit_name, ke.quantity
           FROM kits k
           JOIN kit_elements ke ON k.kit_id = ke.kit_id
           WHERE ke.element_id = ?''', (element_id,)
    ).fetchall()

    return render_template('view_element.html', element=element, kits=kits)


@app.route('/elements/<int:element_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def edit_element(element_id):
    """Edit an element"""
    db = get_db()
    element = db.execute('SELECT * FROM elements WHERE element_id = ?', (element_id,)).fetchone()

    if element is None:
        abort(404)

    if request.method == 'POST':
        item_number = request.form.get('item_number')
        item_description = request.form['item_description']
        type_id = request.form['type_id']
        quantity = request.form['quantity']
        unit_cost = request.form.get('unit_cost') or 0.0
        notes = request.form.get('notes', '')

        error = None
        if not item_description:
            error = 'Item description is required.'
        elif not type_id:
            error = 'Element type is required.'
        elif not quantity or not quantity.isdigit() or int(quantity) < 0:
             error = 'Quantity must be a non-negative number.'
        elif unit_cost:
             try:
                 unit_cost = float(unit_cost)
                 if unit_cost < 0: error = 'Unit cost cannot be negative.'
             except ValueError:
                 error = 'Unit cost must be a valid number.'

        if error:
            flash(error, 'danger')
        else:
            db.execute(
                '''UPDATE elements SET
                   item_number = ?, item_description = ?, type_id = ?, quantity = ?, unit_cost = ?, notes = ?
                   WHERE element_id = ?''',
                (item_number, item_description, type_id, int(quantity), unit_cost, notes, element_id)
            )
            db.commit()
            flash('Element updated successfully.', 'success')
            return redirect(url_for('view_element', element_id=element_id))

    element_types_list = db.execute('SELECT * FROM element_types ORDER BY type_name').fetchall()
    return render_template('edit_element.html', element=element, types=element_types_list)


@app.route('/elements/<int:element_id>/delete', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def delete_element(element_id):
    """Delete an element"""
    db = get_db()

    # Check if element is part of any kits
    kit_count = db.execute('SELECT COUNT(*) FROM kit_elements WHERE element_id = ?', (element_id,)).fetchone()[0]
    if kit_count > 0:
        flash(f'Cannot delete element used in {kit_count} kit(s). Please remove it from kits first.', 'danger')
        return redirect(url_for('elements'))

    # Check if element is assigned to any events (if applicable, e.g., via event_elements table)
    # event_count = db.execute('SELECT COUNT(*) FROM event_elements WHERE element_id = ?', (element_id,)).fetchone()[0]
    # if event_count > 0:
    #     flash(f'Cannot delete element assigned to {event_count} event(s).', 'danger')
    #     return redirect(url_for('elements'))


    db.execute('DELETE FROM elements WHERE element_id = ?', (element_id,))
    db.commit()
    flash('Element deleted successfully.', 'success')
    return redirect(url_for('elements'))


# --- Kit Management Routes (Assuming these exist based on view_element) ---
@app.route('/kits')
@login_required
def kits():
    """List all kits and display statistics"""
    db = get_db()

    # Fetch kits data including element count and total quantity
    kits_data = db.execute('''
        SELECT k.*,
               COUNT(ke.element_id) as element_count,
               COALESCE(SUM(ke.quantity), 0) as total_elements
        FROM kits k
        LEFT JOIN kit_elements ke ON k.kit_id = ke.kit_id
        GROUP BY k.kit_id
        ORDER BY k.kit_name
    ''').fetchall()

    # Convert to list of dicts
    kits_list = [dict(row) for row in kits_data]

    # --- START: Add Statistics Calculation ---
    total_kits = len(kits_list)
    # Sum the 'total_elements' calculated by the SQL query
    total_kit_elements = sum(kit['total_elements'] for kit in kits_list)
    avg_elements_per_kit = round(total_kit_elements / total_kits, 1) if total_kits > 0 else 0

    stats = {
        'total_kits': total_kits,
        'total_kit_elements': total_kit_elements,
        'avg_elements_per_kit': avg_elements_per_kit
    }
    # --- END: Add Statistics Calculation ---

    # Pass both kits list and stats to the template
    return render_template('kits.html', kits=kits_list, stats=stats)

@app.route('/kits/new', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def new_kit():
    db = get_db()
    if request.method == 'POST':
        kit_name = request.form['kit_name']
        description = request.form.get('description', '')
        notes = request.form.get('notes', '')
        element_ids = request.form.getlist('element_ids')
        element_qtys = {}
        for el_id in element_ids:
            qty_key = f'element_qty_{el_id}'
            if qty_key in request.form:
                try:
                    qty = int(request.form[qty_key])
                    if qty > 0: element_qtys[el_id] = qty
                except ValueError: pass # Ignore invalid quantities

        error = None
        if not kit_name: error = 'Kit name is required.'
        elif not element_qtys: error = 'Kit must contain at least one element.'

        if error:
            flash(error, 'danger')
        else:
            cursor = db.execute(
                'INSERT INTO kits (kit_name, description, notes) VALUES (?, ?, ?)',
                (kit_name, description, notes)
            )
            kit_id = cursor.lastrowid
            for el_id, qty in element_qtys.items():
                db.execute(
                    'INSERT INTO kit_elements (kit_id, element_id, quantity) VALUES (?, ?, ?)',
                    (kit_id, el_id, qty)
                )
            db.commit()
            flash('Kit created successfully.', 'success')
            return redirect(url_for('kits'))

    elements_list = db.execute('SELECT * FROM elements ORDER BY item_description').fetchall()
    return render_template('new_kit.html', elements=elements_list)


@app.route('/kits/<int:kit_id>')
@login_required
def view_kit(kit_id):
    db = get_db()
    kit = db.execute('SELECT * FROM kits WHERE kit_id = ?', (kit_id,)).fetchone()
    if not kit: abort(404)

    kit_elements = db.execute(
        '''SELECT e.element_id, e.item_number, e.item_description, ke.quantity
           FROM elements e
           JOIN kit_elements ke ON e.element_id = ke.element_id
           WHERE ke.kit_id = ?''', (kit_id,)
    ).fetchall()

    # Check usage in events (assuming event_kits table)
    event_usage = db.execute(
        '''SELECT COUNT(ek.event_id) as count
           FROM event_kits ek
           WHERE ek.kit_id = ?''', (kit_id,)
    ).fetchone()['count']


    return render_template('view_kit.html', kit=kit, elements=kit_elements, event_usage=event_usage)


@app.route('/kits/<int:kit_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def edit_kit(kit_id):
    db = get_db()
    kit = db.execute('SELECT * FROM kits WHERE kit_id = ?', (kit_id,)).fetchone()
    if not kit: abort(404)

    if request.method == 'POST':
        kit_name = request.form['kit_name']
        description = request.form.get('description', '')
        notes = request.form.get('notes', '')
        element_ids = request.form.getlist('element_ids')
        element_qtys = {}
        for el_id in element_ids:
            qty_key = f'element_qty_{el_id}'
            if qty_key in request.form:
                try:
                    qty = int(request.form[qty_key])
                    if qty > 0: element_qtys[el_id] = qty
                except ValueError: pass

        error = None
        if not kit_name: error = 'Kit name is required.'
        elif not element_qtys: error = 'Kit must contain at least one element.'

        if error:
            flash(error, 'danger')
        else:
            db.execute(
                'UPDATE kits SET kit_name = ?, description = ?, notes = ? WHERE kit_id = ?',
                (kit_name, description, notes, kit_id)
            )
            # Update elements - remove old, add new
            db.execute('DELETE FROM kit_elements WHERE kit_id = ?', (kit_id,))
            for el_id, qty in element_qtys.items():
                db.execute(
                    'INSERT INTO kit_elements (kit_id, element_id, quantity) VALUES (?, ?, ?)',
                    (kit_id, el_id, qty)
                )
            db.commit()
            flash('Kit updated successfully.', 'success')
            return redirect(url_for('view_kit', kit_id=kit_id))

    # Get current elements in kit
    current_elements_data = db.execute(
        '''SELECT element_id, quantity FROM kit_elements WHERE kit_id = ?''', (kit_id,)
    ).fetchall()
    current_elements = {item['element_id']: item['quantity'] for item in current_elements_data}

    # Get all available elements
    all_elements = db.execute('SELECT * FROM elements ORDER BY item_description').fetchall()

    return render_template('edit_kit.html', kit=kit, all_elements=all_elements, current_elements=current_elements)


@app.route('/kits/<int:kit_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_kit(kit_id):
    db = get_db()
    # Check usage in events (assuming event_kits table)
    event_usage = db.execute(
        '''SELECT COUNT(ek.event_id) as count
           FROM event_kits ek
           WHERE ek.kit_id = ?''', (kit_id,)
    ).fetchone()['count']

    if event_usage > 0:
        flash(f'Cannot delete kit assigned to {event_usage} event(s). Please remove assignments first.', 'danger')
        return redirect(url_for('kits'))

    # Delete kit elements first
    db.execute('DELETE FROM kit_elements WHERE kit_id = ?', (kit_id,))
    # Delete the kit
    db.execute('DELETE FROM kits WHERE kit_id = ?', (kit_id,))
    db.commit()
    flash('Kit deleted successfully.', 'success')
    return redirect(url_for('kits'))


# --- Invoice Routes (Assuming these exist based on view_client) ---
@app.route('/invoices')
@login_required
def invoices():
    db = get_db()
    invoices_list = db.execute(
        '''SELECT i.*, c.name as client_name, e.event_name
           FROM invoices i
           JOIN clients c ON i.client_id = c.id
           LEFT JOIN events e ON i.event_id = e.event_id
           ORDER BY i.issue_date DESC'''
    ).fetchall()
    return render_template('invoices.html', invoices=invoices_list)

@app.route('/invoices/<int:invoice_id>')
@login_required
def view_invoice(invoice_id):
    db = get_db()
    invoice = db.execute(
        '''SELECT i.*, c.name as client_name, c.address as client_address,
                  c.city as client_city, c.state as client_state, c.zip as client_zip,
                  e.event_name, e.event_date
           FROM invoices i
           JOIN clients c ON i.client_id = c.id
           LEFT JOIN events e ON i.event_id = e.event_id
           WHERE i.id = ?''', (invoice_id,)
    ).fetchone()
    if not invoice: abort(404)

    # Note: invoice_items table doesn't exist yet, passing empty list for now
    invoice_items = []

    return render_template('view_invoice.html', invoice=invoice, items=invoice_items)


@app.route('/invoices/<int:invoice_id>/pdf')
@login_required
def generate_invoice_pdf(invoice_id):
    if not weasyprint_available:
        flash('PDF generation is not available on this server.', 'danger')
        return redirect(url_for('view_invoice', invoice_id=invoice_id))

    db = get_db()
    invoice = db.execute(
        '''SELECT i.*, c.name as client_name, c.address as client_address,
                  c.city as client_city, c.state as client_state, c.zip as client_zip,
                  e.event_name, e.event_date
           FROM invoices i
           JOIN clients c ON i.client_id = c.id
           LEFT JOIN events e ON i.event_id = e.event_id
           WHERE i.id = ?''', (invoice_id,)
    ).fetchone()
    if not invoice: abort(404)

    # Note: invoice_items table doesn't exist yet, passing empty list for now
    invoice_items = []

    # Render HTML template for the PDF
    html_content = render_template('invoice_pdf.html', invoice=invoice, items=invoice_items)

    # Generate PDF using WeasyPrint
    pdf_file = HTML(string=html_content).write_pdf()

    # Send the PDF file as a response
    return Response(pdf_file, mimetype='application/pdf', headers={
        'Content-Disposition': f'inline; filename=invoice_{invoice_id}.pdf'
    })


# --- Register Blueprints ---
# Make sure blueprints are imported correctly
try:
    from blueprints.calendar_bp import calendar_bp
    from blueprints.locations_bp import locations_bp
    from blueprints.tasks_bp import tasks_bp
    app.register_blueprint(calendar_bp)
    app.register_blueprint(locations_bp)
    app.register_blueprint(tasks_bp)
    print("Blueprints registered successfully.")
except ImportError as e:
    print(f"Warning: Could not import or register blueprints: {e}")


if __name__ == '__main__':
    # Use a different port if default 5000 is taken
    port = int(os.environ.get('PORT', 5004))
    # Run in debug mode for development, disable for production
    app.run(debug=True, host='0.0.0.0', port=port)
