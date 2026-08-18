import sqlite3
import hashlib
from datetime import datetime, timedelta

DB_PATH = "dataset/auth.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_auth_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            failed_attempts INTEGER DEFAULT 0,
            is_locked INTEGER DEFAULT 0,
            locked_until TEXT
        )
    """)
    
    # Create default accounts if empty: admin/admin123 and analyst/user123
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()
        cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", 
                       ("admin", hash_pw("admin123"), "admin", 0, 0, None))
        cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", 
                       ("analyst_bob", hash_pw("user123"), "user", 0, 0, None))
        conn.commit()
    conn.close()

def authenticate_user(username, password, max_attempts=3):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return False, "User not found."

    # Check Lockout status
    if user["is_locked"]:
        if user["locked_until"]:
            lock_expiry = datetime.fromisoformat(user["locked_until"])
            if datetime.now() < lock_expiry:
                conn.close()
                return False, f"Account locked until {lock_expiry.strftime('%Y-%m-%d %H:%M')}. Contact Admin to unlock."
            else:
                # 24 hours passed, auto-unlock
                cursor.execute("UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL WHERE username = ?", (username,))
                conn.commit()

    # Verify Password
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if user["password_hash"] == pw_hash:
        cursor.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return True, user["role"]
    else:
        new_attempts = user["failed_attempts"] + 1
        if new_attempts >= max_attempts:
            lock_until = (datetime.now() + timedelta(days=1)).isoformat()
            cursor.execute("UPDATE users SET failed_attempts = ?, is_locked = 1, locked_until = ? WHERE username = ?", 
                           (new_attempts, lock_until, username))
            conn.commit()
            conn.close()
            return False, "Maximum attempts exceeded. Account is locked for 24 hours. Admin has been notified."
        else:
            cursor.execute("UPDATE users SET failed_attempts = ? WHERE username = ?", (new_attempts, username))
            conn.commit()
            remaining = max_attempts - new_attempts
            conn.close()
            return False, f"Incorrect password. {remaining} attempt(s) remaining."

def get_all_locked_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role, failed_attempts, locked_until FROM users WHERE is_locked = 1")
    rows = cursor.fetchall()
    conn.close()
    return rows

def admin_unlock_user(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL WHERE username = ?", (username,))
    conn.commit()
    conn.close()