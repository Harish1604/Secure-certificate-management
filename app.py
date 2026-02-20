"""
Secure Digital Certificate Issuance and Verification System
Main Flask Application
"""
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3
import os
from io import BytesIO

from auth.register import register_user, get_user_by_username
from auth.login import authenticate_user
from auth.otp import send_otp, verify_otp
from access_control.acl import require_auth, require_role
from requests.manage_requests import (
    create_request, get_pending_requests, get_user_requests, 
    approve_request, get_request_by_id
)

from certificates.issue import issue_certificate, get_user_certificates, get_certificate_by_id, get_all_certificates
from certificates.verify import verify_certificate_by_id
from crypto.signature import generate_rsa_keypair

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Paths for RSA keys
PUBLIC_KEY_PATH = 'keys/public_key.pem'
PRIVATE_KEY_PATH = 'keys/private_key.pem'


def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL,
            totp_secret TEXT
        )
    ''')
    
    # Check if totp_secret column exists (migration for existing DB)
    cursor = conn.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'totp_secret' not in columns:
        print("Migrating database: Adding totp_secret to users table...")
        cursor.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    
    # Certificate requests table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificate_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            certificate_type TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            FOREIGN KEY (student_id) REFERENCES users(id)
        )
    ''')
    
    # Certificates table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            request_id INTEGER NOT NULL,
            encrypted_file BLOB NOT NULL,
            encrypted_key TEXT NOT NULL,
            digital_signature TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            issued_at TIMESTAMP NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id),
            FOREIGN KEY (request_id) REFERENCES certificate_requests(id)
        )
    ''')
    
    # OTP codes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    
    # Generate RSA keys if they don't exist
    if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
        print("Generating RSA key pair...")
        generate_rsa_keypair()
        print(f"Keys generated at {PUBLIC_KEY_PATH} and {PRIVATE_KEY_PATH}")


from auth.totp_utils import generate_totp_secret, get_provisioning_uri, generate_qr_code, verify_totp

@app.route('/')
def index():
    """Landing Page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        # Step 1: Username and password
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = authenticate_user(username, password)
        
        if user:
            session['temp_user_id'] = user['id']
            session['temp_username'] = user['username']
            session['temp_role'] = user['role']
            session['temp_totp_secret'] = user.get('totp_secret') # might be None
            
            if user.get('totp_secret'):
                # User has MFA set up -> Verify
                return redirect(url_for('verify_2fa'))
            else:
                # User needs to set up MFA
                return redirect(url_for('setup_2fa'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', step=1)


@app.route('/setup-2fa')
def setup_2fa():
    """MFA Setup Page"""
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
        
    # Generate new secret if not exists
    if 'new_totp_secret' not in session:
        secret = generate_totp_secret()
        session['new_totp_secret'] = secret
    else:
        secret = session['new_totp_secret']
    
    # Generate QR Code
    username = session.get('temp_username', 'User')
    uri = get_provisioning_uri(username, secret)
    qr_code = generate_qr_code(uri)
    
    return render_template('mfa_setup.html', qr_code=qr_code, secret=secret)


@app.route('/setup-mfa-verify', methods=['POST'])
def setup_mfa_verify():
    """Verify and finalize MFA setup"""
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
        
    code = request.form.get('code')
    secret = session.get('new_totp_secret')
    
    if verify_totp(secret, code):
        # Save secret to DB
        user_id = session['temp_user_id']
        conn = sqlite3.connect('database.db')
        conn.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (secret, user_id))
        conn.commit()
        conn.close()
        
        # Log user in
        finalize_login()
        flash('MFA set up successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    flash('Invalid code. Please try again.', 'error')
    return redirect(url_for('setup_2fa'))


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """MFA Verification Page"""
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        code = request.form.get('code')
        # Retrieve secret from session or DB? 
        # We stored it in session['temp_totp_secret'] during login for convenience
        # But for security better to fetch or just use what we have.
        # We grabbed it in login()
        secret = session.get('temp_totp_secret') 
        
        if verify_totp(secret, code):
            finalize_login()
            return redirect(url_for('dashboard'))
        
        flash('Invalid code', 'error')
        
    return render_template('mfa_verify.html')


@app.route('/verify-mfa-login', methods=['POST'])
def verify_mfa_login():
    """Start-point for MFA verify form submission"""
    # This route is pointed to by the verify template form
    return verify_2fa()


def finalize_login():
    """Move temp session vars to permanent session vars"""
    session['user_id'] = session['temp_user_id']
    session['username'] = session['temp_username']
    session['role'] = session['temp_role']
    
    # Clear temp
    session.pop('temp_user_id', None)
    session.pop('temp_username', None)
    session.pop('temp_role', None)
    session.pop('temp_totp_secret', None)
    session.pop('new_totp_secret', None)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role', 'student')
        
        if register_user(username, password, email, role):
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists', 'error')
    
    return render_template('register.html')


@app.route('/dashboard')
@require_auth
def dashboard():
    """Role-based dashboard"""
    role = session.get('role')
    user_id = session.get('user_id')
    
    data = {}
    
    if role == 'student':
        # Get student's requests
        data['requests'] = get_user_requests(user_id)
        data['certificates'] = get_user_certificates(user_id)
    
    elif role == 'admin':
        # Get pending requests
        data['pending_requests'] = get_pending_requests()
        data['certificates'] = get_all_certificates()
    
    elif role == 'verifier':
        # Get all certificates for verification list
        data['certificates'] = get_all_certificates()
    
    return render_template('dashboard.html', role=role, data=data)


@app.route('/request', methods=['GET', 'POST'])
@require_role('student')
def request_certificate():
    """Student certificate request page"""
    if request.method == 'POST':
        certificate_type = request.form.get('certificate_type')
        user_id = session.get('user_id')
        
        request_id = create_request(user_id, certificate_type)
        flash(f'Certificate request submitted! Request ID: {request_id}', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('request.html')


@app.route('/admin/approve/<int:request_id>', methods=['POST'])
@require_role('admin')
def approve_certificate_request(request_id):
    """Admin approves a certificate request"""
    approve_request(request_id)
    flash(f'Request {request_id} approved!', 'success')
    return redirect(url_for('upload_certificate', request_id=request_id))


@app.route('/upload/<int:request_id>', methods=['GET', 'POST'])
@require_role('admin')
def upload_certificate(request_id):
    """Admin uploads and encrypts certificate"""
    req = get_request_by_id(request_id)
    
    if not req:
        flash('Request not found', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        file = request.files.get('certificate_file')
        
        if not file:
            flash('No file uploaded', 'error')
            return render_template('upload.html', request=req)
        
        # Read file data
        file_data = file.read()
        
        # Issue certificate with encryption and signing
        cert_id = issue_certificate(
            request_id,
            file_data,
            PUBLIC_KEY_PATH,
            PRIVATE_KEY_PATH
        )
        
        flash(f'Certificate issued successfully! Certificate ID: {cert_id}', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('upload.html', request=req)


@app.route('/verify', methods=['GET', 'POST'])
@require_role('verifier')
def verify():
    """Verify certificate authenticity"""
    if request.method == 'POST':
        certificate_id = request.form.get('certificate_id')
        
        result = verify_certificate_by_id(
            int(certificate_id),
            PRIVATE_KEY_PATH,
            PUBLIC_KEY_PATH
        )
        
        return render_template('verify.html', result=result, certificate_id=certificate_id)
    
    return render_template('verify.html')


@app.route('/download/<int:certificate_id>')
@require_auth
def download_certificate(certificate_id):
    """Download decrypted certificate (only owner or admin)"""
    user_id = session.get('user_id')
    role = session.get('role')
    
    cert = get_certificate_by_id(certificate_id)
    
    if not cert:
        flash('Certificate not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Check permission
    if role != 'admin' and cert['owner_id'] != user_id:
        flash('You do not have permission to download this certificate', 'error')
        return redirect(url_for('dashboard'))
    
    # Verify and decrypt
    result = verify_certificate_by_id(certificate_id, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    
    if result['valid']:
        return send_file(
            BytesIO(result['decrypted_file']),
            as_attachment=True,
            download_name=f"certificate_{certificate_id}.pdf",
            mimetype='application/pdf'
        )
    else:
        flash('Certificate verification failed', 'error')
        return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Create some default users for testing
    try:
        register_user('student1', 'password123', 'student@test.com', 'student')
        register_user('admin1', 'admin123', 'admin@test.com', 'admin')
        register_user('verifier1', 'verify123', 'verifier@test.com', 'verifier')
        print("\nDefault users created:")
        print("  Student: student1 / password123")
        print("  Admin: admin1 / admin123")
        print("  Verifier: verifier1 / verify123\n")
    except:
        print("\nDefault users already exist\n")
    
    app.run(debug=True, port=5000)
