# CloudVault - Database Module
# Handles SQLite database initialization and connection management
# Uses SQLite for simplicity (student project), can be migrated to PostgreSQL later

import sqlite3
import os

DB_PATH = None


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path):
    global DB_PATH
    DB_PATH = db_path

    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path, timeout=20)
        conn.execute("PRAGMA foreign_keys=ON")
        cursor = conn.cursor()

        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                storage_quota INTEGER DEFAULT 5368709120,
                storage_used INTEGER DEFAULT 0,
                is_locked INTEGER DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS folders (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                name TEXT NOT NULL,
                parent_id TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (parent_id) REFERENCES folders(id)
            );

            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                mime_type TEXT,
                wrapped_fek TEXT NOT NULL,
                fek_nonce TEXT NOT NULL,
                file_nonce TEXT NOT NULL,
                checksum_sha256 TEXT NOT NULL,
                folder_id TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (folder_id) REFERENCES folders(id)
            );

            CREATE TABLE IF NOT EXISTS file_permissions (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                permission INTEGER DEFAULT 4,
                granted_by TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (granted_by) REFERENCES users(id),
                UNIQUE(file_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS share_links (
                id TEXT PRIMARY KEY,
                file_id TEXT NOT NULL,
                created_by TEXT,
                token TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                expires_at TEXT NOT NULL,
                max_downloads INTEGER DEFAULT -1,
                download_count INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
            CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id);
            CREATE INDEX IF NOT EXISTS idx_permissions_file ON file_permissions(file_id);
            CREATE INDEX IF NOT EXISTS idx_permissions_user ON file_permissions(user_id);
            CREATE INDEX IF NOT EXISTS idx_share_token ON share_links(token);
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
        ''')

        conn.commit()
        conn.close()
