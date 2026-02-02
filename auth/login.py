"""
User login and authentication module
"""
from crypto.hash_utils import verify_password
from auth.register import get_user_by_username


def authenticate_user(username, password):
    """
    Authenticate user with username and password
    Returns user dict if successful, None otherwise
    """
    user = get_user_by_username(username)
    
    if not user:
        return None
    
    if verify_password(password, user['password_hash'], user['salt']):
        return user
    
    return None
