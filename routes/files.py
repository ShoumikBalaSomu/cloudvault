# CloudVault - File Management Routes
# Handles file upload with AES-256 encryption, download with decryption
# Folder management, file delete, rename, move operations
# All files are encrypted before being stored on disk

import os
import uuid
import mimetypes
from datetime import datetime
from flask import Blueprint, request, session, redirect, url_for, render_template, flash, send_file, current_app
import io
from database import get_db
from encryption import derive_master_key, encrypt_file, decrypt_file
from routes.auth import login_required, log_audit

files_bp = Blueprint('files', __name__)


@files_bp.route('/dashboard')
@login_required
def dashboard():
    folder_id = request.args.get('folder')
    db = get_db()

    if folder_id:
        folder = db.execute('SELECT * FROM folders WHERE id = ? AND owner_id = ?',
                            (folder_id, session['user_id'])).fetchone()
        if not folder:
            db.close()
            flash('Folder not found.', 'danger')
            return redirect(url_for('files.dashboard'))
        folders = db.execute('SELECT * FROM folders WHERE parent_id = ? AND owner_id = ? ORDER BY name',
                             (folder_id, session['user_id'])).fetchall()
        files = db.execute('SELECT * FROM files WHERE folder_id = ? AND owner_id = ? ORDER BY filename',
                           (folder_id, session['user_id'])).fetchall()
        breadcrumbs = get_breadcrumbs(db, folder_id)
    else:
        folder = None
        folders = db.execute('SELECT * FROM folders WHERE parent_id IS NULL AND owner_id = ? ORDER BY name',
                             (session['user_id'],)).fetchall()
        files = db.execute('SELECT * FROM files WHERE folder_id IS NULL AND owner_id = ? ORDER BY filename',
                           (session['user_id'],)).fetchall()
        breadcrumbs = []

    user = db.execute('SELECT storage_used, storage_quota FROM users WHERE id = ?',
                      (session['user_id'],)).fetchone()
    db.close()

    storage_used_mb = round(user['storage_used'] / (1024 * 1024), 2)
    storage_quota_mb = round(user['storage_quota'] / (1024 * 1024), 2)
    storage_percent = round((user['storage_used'] / user['storage_quota']) * 100, 1) if user['storage_quota'] > 0 else 0

    return render_template('dashboard.html',
                           files=files, folders=folders, folder=folder,
                           breadcrumbs=breadcrumbs,
                           storage_used=storage_used_mb,
                           storage_quota=storage_quota_mb,
                           storage_percent=storage_percent)


def get_breadcrumbs(db, folder_id):
    crumbs = []
    current = folder_id
    while current:
        f = db.execute('SELECT id, name, parent_id FROM folders WHERE id = ?', (current,)).fetchone()
        if f:
            crumbs.insert(0, {'id': f['id'], 'name': f['name']})
            current = f['parent_id']
        else:
            break
    return crumbs


@files_bp.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('files.dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('files.dashboard'))

    folder_id = request.form.get('folder_id') or None

    plaintext = file.read()
    file_size = len(plaintext)

    db = get_db()
    user = db.execute('SELECT storage_used, storage_quota, salt FROM users WHERE id = ?',
                      (session['user_id'],)).fetchone()

    if user['storage_used'] + file_size > user['storage_quota']:
        db.close()
        flash('Storage quota exceeded. Cannot upload file.', 'danger')
        return redirect(url_for('files.dashboard'))

    master_key = derive_master_key(session['username'], user['salt'])
    encrypted = encrypt_file(plaintext, master_key)

    file_id = str(uuid.uuid4())
    encrypted_filename = file_id + '.enc'
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], encrypted_filename)

    with open(file_path, 'wb') as f:
        f.write(encrypted['ciphertext'])

    mime = mimetypes.guess_type(file.filename)[0] or 'application/octet-stream'

    db.execute('''INSERT INTO files (id, owner_id, filename, file_path, file_size, mime_type,
                  wrapped_fek, fek_nonce, file_nonce, checksum_sha256, folder_id)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
               (file_id, session['user_id'], file.filename, encrypted_filename, file_size, mime,
                encrypted['wrapped_fek'], encrypted['wrap_nonce'], encrypted['nonce'],
                encrypted['checksum'], folder_id))

    db.execute('UPDATE users SET storage_used = storage_used + ? WHERE id = ?',
               (file_size, session['user_id']))
    db.commit()
    db.close()

    log_audit(session['user_id'], 'file_upload', resource=file.filename, details={'size': file_size, 'file_id': file_id})
    flash(f'File "{file.filename}" uploaded and encrypted successfully.', 'success')

    if folder_id:
        return redirect(url_for('files.dashboard', folder=folder_id))
    return redirect(url_for('files.dashboard'))


@files_bp.route('/download/<file_id>')
@login_required
def download(file_id):
    db = get_db()
    file_rec = db.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()

    if not file_rec:
        db.close()
        flash('File not found.', 'danger')
        return redirect(url_for('files.dashboard'))

    has_access = False
    if file_rec['owner_id'] == session['user_id']:
        has_access = True
    else:
        perm = db.execute('SELECT permission FROM file_permissions WHERE file_id = ? AND user_id = ?',
                          (file_id, session['user_id'])).fetchone()
        if perm and perm['permission'] & 4:
            has_access = True

    if not has_access:
        db.close()
        flash('Access denied.', 'danger')
        return redirect(url_for('files.dashboard'))

    owner = db.execute('SELECT salt, username FROM users WHERE id = ?', (file_rec['owner_id'],)).fetchone()
    db.close()

    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_rec['file_path'])
    if not os.path.exists(file_path):
        flash('File not found on disk.', 'danger')
        return redirect(url_for('files.dashboard'))

    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    master_key = derive_master_key(owner['username'], owner['salt'])

    try:
        plaintext = decrypt_file(ciphertext, file_rec['file_nonce'],
                                 file_rec['wrapped_fek'], file_rec['fek_nonce'], master_key)
    except Exception:
        flash('Decryption failed. File may be corrupted.', 'danger')
        return redirect(url_for('files.dashboard'))

    log_audit(session['user_id'], 'file_download', resource=file_rec['filename'], details={'file_id': file_id})

    return send_file(io.BytesIO(plaintext), download_name=file_rec['filename'],
                     as_attachment=True, mimetype=file_rec['mime_type'])


@files_bp.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete(file_id):
    db = get_db()
    file_rec = db.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?',
                          (file_id, session['user_id'])).fetchone()

    if not file_rec:
        db.close()
        flash('File not found or access denied.', 'danger')
        return redirect(url_for('files.dashboard'))

    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file_rec['file_path'])
    if os.path.exists(file_path):
        file_size = os.path.getsize(file_path)
        with open(file_path, 'wb') as f:
            f.write(os.urandom(file_size))
        os.remove(file_path)

    db.execute('DELETE FROM files WHERE id = ?', (file_id,))
    db.execute('UPDATE users SET storage_used = MAX(0, storage_used - ?) WHERE id = ?',
               (file_rec['file_size'], session['user_id']))
    db.commit()

    folder_id = file_rec['folder_id']
    db.close()

    log_audit(session['user_id'], 'file_delete', resource=file_rec['filename'], details={'file_id': file_id})
    flash(f'File "{file_rec["filename"]}" securely deleted.', 'success')

    if folder_id:
        return redirect(url_for('files.dashboard', folder=folder_id))
    return redirect(url_for('files.dashboard'))


@files_bp.route('/rename/<file_id>', methods=['POST'])
@login_required
def rename(file_id):
    new_name = request.form.get('new_name', '').strip()
    if not new_name:
        flash('File name cannot be empty.', 'danger')
        return redirect(url_for('files.dashboard'))

    db = get_db()
    file_rec = db.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?',
                          (file_id, session['user_id'])).fetchone()
    if not file_rec:
        db.close()
        flash('File not found.', 'danger')
        return redirect(url_for('files.dashboard'))

    old_name = file_rec['filename']
    db.execute('UPDATE files SET filename = ?, updated_at = ? WHERE id = ?',
               (new_name, datetime.now().isoformat(), file_id))
    db.commit()
    folder_id = file_rec['folder_id']
    db.close()

    log_audit(session['user_id'], 'file_rename', resource=new_name, details={'old_name': old_name})
    flash(f'File renamed to "{new_name}".', 'success')

    if folder_id:
        return redirect(url_for('files.dashboard', folder=folder_id))
    return redirect(url_for('files.dashboard'))


@files_bp.route('/create-folder', methods=['POST'])
@login_required
def create_folder():
    name = request.form.get('folder_name', '').strip()
    parent_id = request.form.get('parent_id') or None

    if not name:
        flash('Folder name required.', 'danger')
        return redirect(url_for('files.dashboard'))

    folder_id = str(uuid.uuid4())
    db = get_db()
    db.execute('INSERT INTO folders (id, owner_id, name, parent_id) VALUES (?, ?, ?, ?)',
               (folder_id, session['user_id'], name, parent_id))
    db.commit()
    db.close()

    log_audit(session['user_id'], 'folder_create', resource=name)
    flash(f'Folder "{name}" created.', 'success')

    if parent_id:
        return redirect(url_for('files.dashboard', folder=parent_id))
    return redirect(url_for('files.dashboard'))


@files_bp.route('/delete-folder/<folder_id>', methods=['POST'])
@login_required
def delete_folder(folder_id):
    db = get_db()
    folder = db.execute('SELECT * FROM folders WHERE id = ? AND owner_id = ?',
                        (folder_id, session['user_id'])).fetchone()
    if not folder:
        db.close()
        flash('Folder not found.', 'danger')
        return redirect(url_for('files.dashboard'))

    files_in_folder = db.execute('SELECT id FROM files WHERE folder_id = ?', (folder_id,)).fetchall()
    subfolders = db.execute('SELECT id FROM folders WHERE parent_id = ?', (folder_id,)).fetchall()

    if files_in_folder or subfolders:
        db.close()
        flash('Folder is not empty. Delete files and subfolders first.', 'danger')
        return redirect(url_for('files.dashboard'))

    parent_id = folder['parent_id']
    db.execute('DELETE FROM folders WHERE id = ?', (folder_id,))
    db.commit()
    db.close()

    log_audit(session['user_id'], 'folder_delete', resource=folder['name'])
    flash(f'Folder "{folder["name"]}" deleted.', 'success')

    if parent_id:
        return redirect(url_for('files.dashboard', folder=parent_id))
    return redirect(url_for('files.dashboard'))
