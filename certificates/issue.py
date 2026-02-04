"""
Certificate issuance module
Handles encryption, signing, and storage of certificates
"""
import sqlite3
from datetime import datetime
from crypto.encryption import generate_aes_key, encrypt_file_aes, encrypt_key_rsa
from crypto.signature import sign_data
from crypto.hash_utils import hash_file
from utils.encoding import encode_base64


def issue_certificate(request_id, file_data, public_key_path, private_key_path):
    """
    Issue a certificate with full encryption and signing
    
    Process:
    1. Generate random AES key
    2. Encrypt certificate file with AES
    3. Encrypt AES key with RSA public key
    4. Hash encrypted file with SHA-256
    5. Sign hash with RSA private key
    6. Store in database
    
    Returns: certificate_id
    """
    # Step 1: Generate AES key
    aes_key = generate_aes_key()
    
    # Step 2: Encrypt file with AES
    encrypted_file = encrypt_file_aes(file_data, aes_key)
    
    # Step 3: Encrypt AES key with RSA
    encrypted_key = encrypt_key_rsa(aes_key, public_key_path)
    
    # Step 4: Hash the encrypted file
    file_hash = hash_file(encrypted_file)
    
    # Step 5: Sign the hash
    signature = sign_data(file_hash.encode('utf-8'), private_key_path)
    
    # Encode encrypted key and signature to Base64 for storage
    encrypted_key_b64 = encode_base64(encrypted_key)
    signature_b64 = encode_base64(signature)
    
    # Get request details
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT student_id FROM certificate_requests WHERE id = ?', (request_id,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        raise ValueError("Request not found")
    
    owner_id = result[0]
    issued_at = datetime.now()
    
    # Store certificate
    cursor.execute('''
        INSERT INTO certificates (owner_id, request_id, encrypted_file, encrypted_key, digital_signature, file_hash, issued_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (owner_id, request_id, encrypted_file, encrypted_key_b64, signature_b64, file_hash, issued_at))
    
    certificate_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return certificate_id


def get_user_certificates(user_id):
    """Get all certificates for a user"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT c.id, cr.certificate_type, c.issued_at
        FROM certificates c
        JOIN certificate_requests cr ON c.request_id = cr.id
        WHERE c.owner_id = ?
        ORDER BY c.issued_at DESC
    ''', (user_id,))
    
    certs = cursor.fetchall()
    conn.close()
    
    return [
        {
            'id': c[0],
            'certificate_type': c[1],
            'issued_at': c[2]
        }
        for c in certs
    ]


def get_certificate_by_id(certificate_id):
    """Get certificate details by ID"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT c.id, c.owner_id, c.encrypted_file, c.encrypted_key, c.digital_signature, c.file_hash, cr.certificate_type
        FROM certificates c
        JOIN certificate_requests cr ON c.request_id = cr.id
        WHERE c.id = ?
    ''', (certificate_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            'id': result[0],
            'owner_id': result[1],
            'encrypted_file': result[2],
            'encrypted_key': result[3],
            'digital_signature': result[4],
            'file_hash': result[5],
            'certificate_type': result[6]
        }
    return None


def get_all_certificates():
    """Get all issued certificates with owner details (For Admin)"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT c.id, cr.certificate_type, c.issued_at, u.username
        FROM certificates c
        JOIN certificate_requests cr ON c.request_id = cr.id
        JOIN users u ON c.owner_id = u.id
        ORDER BY c.issued_at DESC
    ''')
    
    certs = cursor.fetchall()
    conn.close()
    
    return [
        {
            'id': c[0],
            'certificate_type': c[1],
            'issued_at': c[2],
            'owner': c[3]
        }
        for c in certs
    ]
