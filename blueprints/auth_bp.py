"""Authentication and user management blueprint."""
from flask import Blueprint, render_template, redirect, url_for, flash, session

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
from helpers import login_required, role_required, get_current_user
from services import auth_service


auth_bp = Blueprint('auth', __name__, url_prefix='')


def flash_form_errors(form):
    """Flash WTForms validation errors with field context."""
    for field_name, errors in form.errors.items():
        field = getattr(form, field_name)
        label = field.label.text if field and field.label else field_name.replace('_', ' ').title()
        for error in errors:
            flash(f"{label}: {error}", 'danger')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = auth_service.authenticate_user(username, password)

        if not user:
            form.password.errors.append('Invalid username or password')
            flash_form_errors(form)
        else:
            auth_service.update_last_login(user['id'])
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful', 'success')
            return redirect(url_for('index'))
    elif form.is_submitted():
        flash_form_errors(form)

    return render_template('login.html', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip()
        full_name = form.full_name.data.strip()
        password = form.password.data

        if auth_service.is_username_taken(username):
            form.username.errors.append(f'User {username} is already registered')
        if auth_service.is_email_taken(email):
            form.email.errors.append(f'Email {email} is already registered')

        if form.errors:
            flash_form_errors(form)
        else:
            auth_service.create_user(username, password, email, full_name, role='viewer')
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('auth.login'))
    elif form.is_submitted():
        flash_form_errors(form)

    return render_template('register.html', form=form)


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.email.data.strip()
        user = auth_service.fetch_user_by_email(email)

        if user is None:
            flash('If your email is registered, you will receive password reset instructions.', 'info')
            return redirect(url_for('auth.login'))

        token = auth_service.create_password_reset_token(user['id'])
        reset_url = url_for('auth.reset_password', token=token, _external=True)
        flash(f'Password reset link (would be emailed in production): {reset_url}', 'info')
        return redirect(url_for('auth.login'))
    elif form.is_submitted():
        flash_form_errors(form)

    return render_template('forgot_password.html', form=form)


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_data = auth_service.fetch_valid_reset_token(token)

    if token_data is None:
        flash('Invalid or expired reset token. Please request a new one.', 'danger')
        return redirect(url_for('auth.login'))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        auth_service.change_user_password(token_data['user_id'], form.password.data)
        auth_service.mark_reset_token_used(token_data['id'])
        flash('Password has been reset! You can now login with your new password.', 'success')
        return redirect(url_for('auth.login'))
    elif form.is_submitted():
        flash_form_errors(form)

    return render_template('reset_password.html', token=token, form=form)


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = get_current_user()
    profile_form = ProfileForm(data={'full_name': user['full_name'], 'email': user['email']})
    password_form = PasswordChangeForm()

    if profile_form.submit_profile.data:
        if profile_form.validate():
            email = profile_form.email.data.strip()
            full_name = profile_form.full_name.data.strip()

            if auth_service.is_email_taken(email, exclude_user_id=user['id']):
                profile_form.email.errors.append('Email is already in use by another account')
                flash_form_errors(profile_form)
            else:
                auth_service.update_user_profile(user['id'], email, full_name)
                flash('Profile updated successfully', 'success')
                return redirect(url_for('auth.profile'))
        else:
            flash_form_errors(profile_form)

    elif password_form.submit_password.data:
        if password_form.validate():
            current_password = password_form.current_password.data
            if not auth_service.authenticate_user(user['username'], current_password):
                password_form.current_password.errors.append('Current password is incorrect')
                flash_form_errors(password_form)
            else:
                auth_service.change_user_password(user['id'], password_form.new_password.data)
                flash('Password updated successfully', 'success')
                return redirect(url_for('auth.profile'))
        else:
            flash_form_errors(password_form)

    return render_template('profile.html', user=user, profile_form=profile_form, password_form=password_form)


@auth_bp.route('/users')
@login_required
@role_required('admin')
def manage_users():
    users = auth_service.fetch_all_users()
    return render_template('users.html', users=users)


@auth_bp.route('/users/new', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def new_user():
    form = UserCreateForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip()
        full_name = form.full_name.data.strip()
        role = form.role.data
        password = form.password.data

        if auth_service.is_username_taken(username):
            form.username.errors.append(f'User {username} is already registered')
        if auth_service.is_email_taken(email):
            form.email.errors.append(f'Email {email} is already registered')

        if form.errors:
            flash_form_errors(form)
        else:
            auth_service.create_user(username, password, email, full_name, role)
            flash('User created successfully!', 'success')
            return redirect(url_for('auth.manage_users'))
    elif form.is_submitted():
        flash_form_errors(form)

    return render_template('new_user.html', form=form)


@auth_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    user = auth_service.fetch_user_by_id(user_id)
    if user is None:
        flash('User not found', 'danger')
        return redirect(url_for('auth.manage_users'))

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
        new_password = form.new_password.data or None

        if auth_service.is_username_taken(username, exclude_user_id=user_id):
            form.username.errors.append('Username is already in use by another account')
        if auth_service.is_email_taken(email, exclude_user_id=user_id):
            form.email.errors.append('Email is already in use by another account')

        if form.errors:
            flash_form_errors(form)
        else:
            auth_service.update_user_account(
                user_id,
                username=username,
                email=email,
                full_name=full_name,
                role=role,
                new_password=new_password,
            )
            flash('User updated successfully', 'success')
            return redirect(url_for('auth.manage_users'))
    elif form.is_submitted():
        flash_form_errors(form)

    return render_template('edit_user.html', user=user, form=form)


@auth_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('auth.manage_users'))

    auth_service.delete_user(user_id)
    flash('User deleted successfully', 'success')
    return redirect(url_for('auth.manage_users'))


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('landing'))
