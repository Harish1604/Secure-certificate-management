"""
Access Control List (ACL) module for role-based authorization
"""
from functools import wraps
from flask import session, redirect, url_for, flash


# Define permissions for each role
PERMISSIONS = {
    'student': [
        'login',
        'request_certificate',
        'view_own_certificates',
        'view_own_requests'
    ],
    'admin': [
        'login',
        'approve_request',
        'upload_certificate',
        'encrypt_sign',
        'view_own_certificates',
        'verify_certificate',
        'view_all_requests'
    ],
    'verifier': [
        'login',
        'verify_certificate'
    ]
}


def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def require_role(*allowed_roles):
    """Decorator to require specific role(s)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page', 'error')
                return redirect(url_for('login'))
            
            if session.get('role') not in allowed_roles:
                flash('You do not have permission to access this page', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_permission(user_role, action):
    """
    Check if a user role has permission for an action
    Returns True if allowed, False otherwise
    """
    if user_role not in PERMISSIONS:
        return False
    
    return action in PERMISSIONS[user_role]
