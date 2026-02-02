"""
Hash utilities for password hashing and file hashing using SHA-256
"""
import hashlib
import secrets


def generate_salt(length=32):
    """Generate a random salt for password hashing"""
    return secrets.token_hex(length)


def hash_password(password, salt):
    """Hash a password using SHA-256 with salt"""
    salted_password = (password + salt).encode('utf-8')
    return hashlib.sha256(salted_password).hexdigest()


def verify_password(password, stored_hash, salt):
    """Verify a password against stored hash"""
    return hash_password(password, salt) == stored_hash


def hash_file(file_data):
    """Generate SHA-256 hash of file data"""
    return hashlib.sha256(file_data).hexdigest()
