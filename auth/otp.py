"""
OTP (One-Time Password) module for multi-factor authentication
"""
import sqlite3
import secrets
from datetime import datetime, timedelta


def generate_otp():
    """Generate a 6-digit OTP"""
    return str(secrets.randbelow(1000000)).zfill(6)


def send_otp(user_id, email):
    """
    Generate and send OTP to user
    For demo purposes, prints to console
    Returns the OTP code
    """
    otp_code = generate_otp()
    
    # Store OTP in database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Delete any existing unused OTPs for this user
    cursor.execute('DELETE FROM otp_codes WHERE user_id = ? AND used = 0', (user_id,))
    
    # Create new OTP (expires in 5 minutes)
    created_at = datetime.now()
    expires_at = created_at + timedelta(minutes=5)
    
    cursor.execute('''
        INSERT INTO otp_codes (user_id, code, created_at, expires_at, used)
        VALUES (?, ?, ?, ?, 0)
    ''', (user_id, otp_code, created_at, expires_at))
    
    conn.commit()
    conn.close()
    
    # For demo: print to console instead of sending email
    print(f"\n{'='*50}")
    print(f"OTP for {email}: {otp_code}")
    print(f"Valid for 5 minutes")
    print(f"{'='*50}\n")
    
    return otp_code


def verify_otp(user_id, code):
    """
    Verify OTP code for user
    Returns True if valid, False otherwise
    """
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, expires_at FROM otp_codes 
        WHERE user_id = ? AND code = ? AND used = 0
    ''', (user_id, code))
    
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return False
    
    otp_id, expires_at = result
    expires_at = datetime.fromisoformat(expires_at)
    
    # Check if expired
    if datetime.now() > expires_at:
        conn.close()
        return False
    
    # Mark OTP as used
    cursor.execute('UPDATE otp_codes SET used = 1 WHERE id = ?', (otp_id,))
    conn.commit()
    conn.close()
    
    return True
