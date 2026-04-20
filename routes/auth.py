# CloudVault - Authentication Routes
# Handles user registration, login, logout with bcrypt hashing
# Implements rate limiting and account lockout for brute-force protection
# JWT tokens stored in session for simplicity (student project)

import uuid
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, session, redirect, url_for, render_template, flash, jsonify
import bcrypt
from database import get_db
from encryption import generate_salt

auth_bp = Blueprint('auth', __name__)

LOGIN_ATTEMPT_LIMIT = 5
LOCKOUT_DURATION_MINUTES = 30


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue.', 'warning')
            return redirect(url_for('auth.login_page'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue.', 'warning')
            return redirect(url_for('auth.login_page'))
        if session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('files.dashboard'))
        return f(*args, **kwargs)
    return decorated


def log_audit(user_id, action, resource=None, details=None):
    db = get_db()
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')
    db.execute(
        'INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?, ?)',
        (user_id, action, resource, ip, ua, json.dumps(details) if details else None)
    )
    db.commit()
    db.close()


@auth_bp.route('/login', methods=['GET'])
def login_page():
    if 'user_id' in session:
        return redirect(url_for('files.dashboard'))
    return render_template('login.html')


@auth_bp.route('/register', methods=['GET'])
def register_page():
    if 'user_id' in session:
        return redirect(url_for('files.dashboard'))
    return render_template('register.html')


@auth_bp.route('/register', methods=['POST'])
def register():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not username or not email or not password:
        flash('All fields are required.', 'danger')
        return redirect(url_for('auth.register_page'))

    if len(username) < 3 or len(username) > 50:
        flash('Username must be between 3 and 50 characters.', 'danger')
        return redirect(url_for('auth.register_page'))

    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'danger')
        return redirect(url_for('auth.register_page'))

    if password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('auth.register_page'))

    db = get_db()
    existing = db.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email)).fetchone()
    if existing:
        db.close()
        flash('Username or email already exists.', 'danger')
        return redirect(url_for('auth.register_page'))

    user_id = str(uuid.uuid4())
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    salt = generate_salt()

    db.execute(
        'INSERT INTO users (id, username, email, password_hash, salt, role) VALUES (?, ?, ?, ?, ?, ?)',
        (user_id, username, email, password_hash, salt, 'user')
    )
    db.commit()
    db.close()

    log_audit(user_id, 'register', resource=username, details={'email': email})
    flash('Account created successfully! Please login.', 'success')
    return redirect(url_for('auth.login_page'))


@auth_bp.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        flash('Username and password required.', 'danger')
        return redirect(url_for('auth.login_page'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    if not user:
        db.close()
        log_audit(None, 'login_failed', resource=username, details={'reason': 'user not found'})
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('auth.login_page'))

    if user['is_locked']:
        locked_until = user['locked_until']
        if locked_until and datetime.fromisoformat(locked_until) > datetime.now():
            db.close()
            remaining = (datetime.fromisoformat(locked_until) - datetime.now()).seconds // 60
            log_audit(user['id'], 'login_blocked', resource=username, details={'reason': 'account locked'})
            flash(f'Account locked. Try again in {remaining} minutes.', 'danger')
            return redirect(url_for('auth.login_page'))
        else:
            db.execute('UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?', (user['id'],))
            db.commit()

    if not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        attempts = user['failed_attempts'] + 1
        if attempts >= LOGIN_ATTEMPT_LIMIT:
            lock_time = (datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat()
            db.execute('UPDATE users SET failed_attempts = ?, is_locked = 1, locked_until = ? WHERE id = ?',
                       (attempts, lock_time, user['id']))
            db.commit()
            db.close()
            log_audit(user['id'], 'account_locked', resource=username, details={'attempts': attempts})
            flash(f'Account locked after {LOGIN_ATTEMPT_LIMIT} failed attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes.', 'danger')
            return redirect(url_for('auth.login_page'))
        else:
            db.execute('UPDATE users SET failed_attempts = ? WHERE id = ?', (attempts, user['id']))
            db.commit()
            db.close()
            remaining = LOGIN_ATTEMPT_LIMIT - attempts
            log_audit(user['id'], 'login_failed', resource=username, details={'attempts': attempts})
            flash(f'Invalid password. {remaining} attempts remaining.', 'danger')
            return redirect(url_for('auth.login_page'))

    db.execute('UPDATE users SET failed_attempts = 0, is_locked = 0, locked_until = NULL WHERE id = ?', (user['id'],))
    db.commit()
    db.close()

    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session['salt'] = user['salt']
    session.permanent = True

    log_audit(user['id'], 'login_success', resource=username)
    flash(f'Welcome back, {user["username"]}!', 'success')
    return redirect(url_for('files.dashboard'))


@auth_bp.route('/logout', methods=['POST', 'GET'])
def logout():
    user_id = session.get('user_id')
    username = session.get('username')
    if user_id:
        log_audit(user_id, 'logout', resource=username)
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('auth.login_page'))


@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_password or not new_password:
        flash('All fields required.', 'danger')
        return redirect(url_for('files.dashboard'))

    if len(new_password) < 8:
        flash('New password must be at least 8 characters.', 'danger')
        return redirect(url_for('files.dashboard'))

    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('files.dashboard'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if not bcrypt.checkpw(current_password.encode(), user['password_hash'].encode()):
        db.close()
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('files.dashboard'))

    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(rounds=12)).decode()
    new_salt = generate_salt()
    db.execute('UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE id = ?',
               (new_hash, new_salt, datetime.now().isoformat(), session['user_id']))
    db.commit()
    db.close()

    session['salt'] = new_salt
    log_audit(session['user_id'], 'password_changed')
    flash('Password changed successfully.', 'success')
    return redirect(url_for('files.dashboard'))
