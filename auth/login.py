import sqlite3
from crypto.hash_utils import verify_password

def login_user(username, password):
    try:
        with sqlite3.connect("database.db", timeout=30) as conn:
            cur = conn.cursor()
            cur.execute("SELECT password_hash, salt, role FROM users WHERE username=?", (username,))
            row = cur.fetchone()

        if not row:
            return False, None

        stored_hash, salt, role = row
        if verify_password(password, stored_hash, salt):
            return True, role

        return False, None
    except sqlite3.Error:
        return False, None

    return False, None
