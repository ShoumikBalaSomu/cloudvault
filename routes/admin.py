# CloudVault - Admin Routes
# Admin panel for user management, audit logs, system stats
# Only accessible by users with admin role
# Provides overview of system security events

import json
from flask import Blueprint, request, session, redirect, url_for, render_template, flash
from database import get_db
from routes.auth import admin_required, log_audit

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/panel')
@admin_required
def panel():
    db = get_db()

    users = db.execute('SELECT id, username, email, role, storage_used, storage_quota, is_locked, failed_attempts, created_at FROM users ORDER BY created_at DESC').fetchall()
    total_users = len(users)
    total_files = db.execute('SELECT COUNT(*) as cnt FROM files').fetchone()['cnt']
    total_storage = db.execute('SELECT COALESCE(SUM(storage_used), 0) as total FROM users').fetchone()['total']
    locked_accounts = db.execute('SELECT COUNT(*) as cnt FROM users WHERE is_locked = 1').fetchone()['cnt']
    recent_logs = db.execute('''SELECT al.*, u.username FROM audit_logs al
                               LEFT JOIN users u ON al.user_id = u.id
                               ORDER BY al.created_at DESC LIMIT 50''').fetchall()
    db.close()

    total_storage_mb = round(total_storage / (1024 * 1024), 2)

    return render_template('admin.html', users=users, total_users=total_users,
                           total_files=total_files, total_storage=total_storage_mb,
                           locked_accounts=locked_accounts, recent_logs=recent_logs)


@admin_bp.route('/lock/<user_id>', methods=['POST'])
@admin_required
def lock_user(user_id):
    if user_id == session['user_id']:
        flash('Cannot lock your own account.', 'danger')
        return redirect(url_for('admin.panel'))

    db = get_db()
    user = db.execute('SELECT username, is_locked FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        db.close()
        flash('User not found.', 'danger')
        return redirect(url_for('admin.panel'))

    new_state = 0 if user['is_locked'] else 1
    db.execute('UPDATE users SET is_locked = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?',
               (new_state, user_id))
    db.commit()
    db.close()

    action = 'account_locked' if new_state else 'account_unlocked'
    log_audit(session['user_id'], action, resource=user['username'])
    status = 'locked' if new_state else 'unlocked'
    flash(f'User "{user["username"]}" has been {status}.', 'success')
    return redirect(url_for('admin.panel'))


@admin_bp.route('/role/<user_id>', methods=['POST'])
@admin_required
def change_role(user_id):
    if user_id == session['user_id']:
        flash('Cannot change your own role.', 'danger')
        return redirect(url_for('admin.panel'))

    new_role = request.form.get('role', 'user')
    if new_role not in ('admin', 'user'):
        flash('Invalid role.', 'danger')
        return redirect(url_for('admin.panel'))

    db = get_db()
    user = db.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        db.close()
        flash('User not found.', 'danger')
        return redirect(url_for('admin.panel'))

    db.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    db.commit()
    db.close()

    log_audit(session['user_id'], 'role_changed', resource=user['username'], details={'new_role': new_role})
    flash(f'User "{user["username"]}" role changed to {new_role}.', 'success')
    return redirect(url_for('admin.panel'))


@admin_bp.route('/delete-user/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('Cannot delete your own account.', 'danger')
        return redirect(url_for('admin.panel'))

    db = get_db()
    user = db.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        db.close()
        flash('User not found.', 'danger')
        return redirect(url_for('admin.panel'))

    db.execute('UPDATE audit_logs SET user_id = NULL WHERE user_id = ?', (user_id,))
    db.execute('UPDATE share_links SET created_by = NULL WHERE created_by = ?', (user_id,))
    db.execute('UPDATE file_permissions SET granted_by = NULL WHERE granted_by = ?', (user_id,))
    
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    db.close()

    log_audit(session['user_id'], 'user_deleted', resource=user['username'])
    flash(f'User "{user["username"]}" deleted.', 'success')
    return redirect(url_for('admin.panel'))


@admin_bp.route('/audit-logs')
@admin_required
def audit_logs():
    page = int(request.args.get('page', 1))
    per_page = 100
    offset = (page - 1) * per_page

    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')

    db = get_db()

    query = '''SELECT al.*, u.username FROM audit_logs al
               LEFT JOIN users u ON al.user_id = u.id WHERE 1=1'''
    params = []

    if action_filter:
        query += ' AND al.action = ?'
        params.append(action_filter)
    if user_filter:
        query += ' AND u.username LIKE ?'
        params.append(f'%{user_filter}%')

    query += ' ORDER BY al.created_at DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])

    logs = db.execute(query, params).fetchall()
    total = db.execute('SELECT COUNT(*) as cnt FROM audit_logs').fetchone()['cnt']
    db.close()

    total_pages = (total + per_page - 1) // per_page

    return render_template('admin.html', show_logs=True, logs=logs,
                           page=page, total_pages=total_pages,
                           action_filter=action_filter, user_filter=user_filter)
