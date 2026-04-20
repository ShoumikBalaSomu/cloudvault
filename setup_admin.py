# CloudVault - Admin Account Setup Script
# Run this once after starting the app to create the default admin account
# Default credentials: admin / admin123 (change immediately after first login)

import os
import sys
import uuid
import bcrypt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, get_db
from encryption import generate_salt

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cloudvault.db')

def create_admin():
    init_db(DB_PATH)
    db = get_db()

    existing = db.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
    if existing:
        print('[!] Admin account already exists.')
        db.close()
        return

    admin_id = str(uuid.uuid4())
    password = 'admin123'
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    salt = generate_salt()

    db.execute(
        'INSERT INTO users (id, username, email, password_hash, salt, role, storage_quota) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (admin_id, 'admin', 'admin@cloudvault.local', password_hash, salt, 'admin', 10737418240)
    )
    db.commit()
    db.close()

    print('[+] Admin account created successfully.')
    print('    Username: admin')
    print('    Password: admin123')
    print('    >>> Change this password after first login! <<<')


if __name__ == '__main__':
    create_admin()
