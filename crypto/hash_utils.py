import hashlib
import os

def hash_password(password: str):
    salt = os.urandom(16)
    hashed = hashlib.sha256(password.encode() + salt).hexdigest()
    return hashed, salt


def verify_password(password: str, stored_hash: str, salt: bytes):
    return hashlib.sha256(password.encode() + salt).hexdigest() == stored_hash

