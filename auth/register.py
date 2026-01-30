import sqlite3
from crypto.hash_utils import hash_password

def register_user(username, password, role):
    hashed, salt = hash_password(password)
    with sqlite3.connect("database.db", timeout=30) as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (username, password_hash, salt, role)
            VALUES (?, ?, ?, ?)
        """, (username, hashed, salt, role))
        conn.commit()
