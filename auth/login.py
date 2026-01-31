import sqlite3
from crypto.hash_utils import verify_password

def login_user(username, password):
    try:
        with sqlite3.connect("database.db", timeout=30) as conn:
            cur = conn.cursor()
            cur.execute("SELECT password_hash, salt, role, totp_secret FROM users WHERE username=?", (username,))
            row = cur.fetchone()

        if not row:
            return False, None, None

        stored_hash, salt, role, totp_secret = row
        if verify_password(password, stored_hash, salt):
            return True, role, totp_secret

        return False, None, None
    except sqlite3.Error:
        return False, None, None

    return False, None, None
