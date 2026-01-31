import sqlite3
from crypto.hash_utils import hash_password
from auth.otp import generate_totp_secret

def register_user(username, password, role):
    hashed, salt = hash_password(password)
    totp_secret = generate_totp_secret()
    
    with sqlite3.connect("database.db", timeout=30) as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (username, password_hash, salt, role, totp_secret)
            VALUES (?, ?, ?, ?, ?)
        """, (username, hashed, salt, role, totp_secret))
        conn.commit()
    
    return totp_secret
