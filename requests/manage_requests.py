"""
Certificate request management module
"""
import sqlite3
from datetime import datetime


def create_request(student_id, certificate_type):
    """
    Create a new certificate request
    Returns request_id if successful
    """
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    created_at = datetime.now()
    
    cursor.execute('''
        INSERT INTO certificate_requests (student_id, certificate_type, status, created_at)
        VALUES (?, ?, 'Pending', ?)
    ''', (student_id, certificate_type, created_at))
    
    request_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return request_id


def get_pending_requests():
    """Get all pending certificate requests (for admin)"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT cr.id, u.username, cr.certificate_type, cr.status, cr.created_at
        FROM certificate_requests cr
        JOIN users u ON cr.student_id = u.id
        WHERE cr.status = 'Pending'
        ORDER BY cr.created_at DESC
    ''')
    
    requests = cursor.fetchall()
    conn.close()
    
    return [
        {
            'id': r[0],
            'student': r[1],
            'certificate_type': r[2],
            'status': r[3],
            'created_at': r[4]
        }
        for r in requests
    ]


def get_user_requests(user_id):
    """Get all certificate requests for a specific user"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, certificate_type, status, created_at
        FROM certificate_requests
        WHERE student_id = ?
        ORDER BY created_at DESC
    ''', (user_id,))
    
    requests = cursor.fetchall()
    conn.close()
    
    return [
        {
            'id': r[0],
            'certificate_type': r[1],
            'status': r[2],
            'created_at': r[3]
        }
        for r in requests
    ]


def approve_request(request_id):
    """Approve a certificate request"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE certificate_requests
        SET status = 'Approved'
        WHERE id = ?
    ''', (request_id,))
    
    conn.commit()
    conn.close()
    
    return True


def get_request_by_id(request_id):
    """Get request details by ID"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT cr.id, cr.student_id, u.username, cr.certificate_type, cr.status
        FROM certificate_requests cr
        JOIN users u ON cr.student_id = u.id
        WHERE cr.id = ?
    ''', (request_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            'id': result[0],
            'student_id': result[1],
            'student': result[2],
            'certificate_type': result[3],
            'status': result[4]
        }
    return None
