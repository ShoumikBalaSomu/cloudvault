# CloudVault - File Sharing Routes
# Handles creating share links with expiry, password protection
# Guest access to shared files without requiring login
# Time-limited and download-limited sharing

import uuid
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, request, session, redirect, url_for, render_template, flash, send_file, current_app
import io
import os
import bcrypt
from database import get_db
from encryption import derive_master_key, decrypt_file
from routes.auth import login_required, log_audit

share_bp = Blueprint('share', __name__)


@share_bp.route('/create/<file_id>', methods=['POST'])
@login_required
def create_share(file_id):
    db = get_db()
    file_rec = db.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?',
                          (file_id, session['user_id'])).fetchone()

    if not file_rec:
        perm = db.execute('SELECT permission FROM file_permissions WHERE file_id = ? AND user_id = ?',
                          (file_id, session['user_id'])).fetchone()
        if not perm or not (perm['permission'] & 1):
            db.close()
            flash('Access denied or file not found.', 'danger')
            return redirect(url_for('files.dashboard'))
        file_rec = db.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()

    hours = int(request.form.get('expires_hours', 24))
    max_downloads = int(request.form.get('max_downloads', -1))
    share_password = request.form.get('share_password', '').strip()

    token = secrets.token_urlsafe(48)
    expires_at = (datetime.now() + timedelta(hours=hours)).isoformat()

    password_hash = None
    if share_password:
        password_hash = bcrypt.hashpw(share_password.encode(), bcrypt.gensalt(rounds=12)).decode()

    share_id = str(uuid.uuid4())
    db.execute('''INSERT INTO share_links (id, file_id, created_by, token, password_hash,
                  expires_at, max_downloads) VALUES (?, ?, ?, ?, ?, ?, ?)''',
               (share_id, file_id, session['user_id'], token, password_hash, expires_at, max_downloads))
    db.commit()
    db.close()

    share_url = request.host_url.rstrip('/') + url_for('share.access_share', token=token)

    log_audit(session['user_id'], 'share_created', resource=file_rec['filename'],
              details={'token': token[:8] + '...', 'expires_hours': hours})

    flash(f'Share link created! URL: {share_url}', 'success')

    folder_id = file_rec['folder_id']
    if folder_id:
        return redirect(url_for('files.dashboard', folder=folder_id))
    return redirect(url_for('files.dashboard'))


@share_bp.route('/<token>', methods=['GET', 'POST'])
def access_share(token):
    db = get_db()
    share = db.execute('SELECT * FROM share_links WHERE token = ? AND is_active = 1', (token,)).fetchone()

    if not share:
        db.close()
        return render_template('shared.html', error='Share link not found or has been deactivated.')

    if datetime.fromisoformat(share['expires_at']) < datetime.now():
        db.close()
        return render_template('shared.html', error='This share link has expired.')

    if share['max_downloads'] != -1 and share['download_count'] >= share['max_downloads']:
        db.close()
        return render_template('shared.html', error='Download limit reached for this share link.')

    file_rec = db.execute('SELECT * FROM files WHERE id = ?', (share['file_id'],)).fetchone()
    if not file_rec:
        db.close()
        return render_template('shared.html', error='Shared file no longer exists.')

    if share['password_hash']:
        if request.method == 'GET':
            db.close()
            return render_template('shared.html', needs_password=True, token=token,
                                   filename=file_rec['filename'], file_size=file_rec['file_size'])

        entered_password = request.form.get('share_password', '')
        if not bcrypt.checkpw(entered_password.encode(), share['password_hash'].encode()):
            db.close()
            return render_template('shared.html', needs_password=True, token=token,
                                   filename=file_rec['filename'], file_size=file_rec['file_size'],
                                   error='Incorrect password.')

    if request.method == 'GET' and not share['password_hash']:
        expires = datetime.fromisoformat(share['expires_at'])
        remaining = expires - datetime.now()
        hours_left = remaining.total_seconds() / 3600
        db.close()
        return render_template('shared.html', file_info=file_rec, token=token,
                               hours_left=round(hours_left, 1),
                               downloads_left=share['max_downloads'] - share['download_count'] if share['max_downloads'] != -1 else 'Unlimited')

    if request.form.get('action') == 'download' or (request.method == 'POST' and share['password_hash']):
        owner = db.execute('SELECT salt, username FROM users WHERE id = ?', (file_rec['owner_id'],)).fetchone()
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_rec['file_path'])

        if not os.path.exists(file_path):
            db.close()
            return render_template('shared.html', error='File not found on server.')

        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        master_key = derive_master_key(owner['username'], owner['salt'])
        try:
            plaintext = decrypt_file(ciphertext, file_rec['file_nonce'],
                                     file_rec['wrapped_fek'], file_rec['fek_nonce'], master_key)
        except Exception:
            db.close()
            return render_template('shared.html', error='Decryption failed.')

        db.execute('UPDATE share_links SET download_count = download_count + 1 WHERE id = ?', (share['id'],))
        db.commit()
        db.close()

        user_id = session.get('user_id')
        log_audit(user_id, 'share_download', resource=file_rec['filename'],
                  details={'token': token[:8] + '...'})

        return send_file(io.BytesIO(plaintext), download_name=file_rec['filename'],
                         as_attachment=True, mimetype=file_rec['mime_type'])

    db.close()
    return redirect(url_for('share.access_share', token=token))


@share_bp.route('/revoke/<share_id>', methods=['POST'])
@login_required
def revoke_share(share_id):
    db = get_db()
    share = db.execute('SELECT * FROM share_links WHERE id = ? AND created_by = ?',
                       (share_id, session['user_id'])).fetchone()
    if not share:
        db.close()
        flash('Share link not found.', 'danger')
        return redirect(url_for('files.dashboard'))

    db.execute('UPDATE share_links SET is_active = 0 WHERE id = ?', (share_id,))
    db.commit()
    db.close()

    log_audit(session['user_id'], 'share_revoked', details={'share_id': share_id})
    flash('Share link revoked.', 'success')
    return redirect(url_for('files.dashboard'))
