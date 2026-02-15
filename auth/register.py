"""
User registration module
"""
import sqlite3
from crypto.hash_utils import generate_salt, hash_password



def register_user(username, password, email, role='student'):
    """
    Register a new user with hashed password
    role: '
    student', 'admin', or 'verifier'
    """
    # Validate role
    if role not in ['student', 'admin', 'verifier']:
        raise ValueError("Invalid role. Must be 'student', 'admin', or 'verifier'")
    
    # Generate salt and hash password
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    
    
    # Insert into database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt, role, email)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password_hash, salt, role, email))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        conn.close()


def get_user_by_username(username):
    """Get user details by username"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'username': user[1],
            'password_hash': user[2],
            'salt': user[3],
            'role': user[4],
            'email': user[5],
            'totp_secret': user[6] if len(user) > 6 else None
        }
    return None


