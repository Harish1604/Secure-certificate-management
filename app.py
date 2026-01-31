from flask import Flask, render_template, request, redirect, session
from auth.login import login_user
from auth.register import register_user
from auth.otp import generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp
from access_control.acl import has_permission
from crypto.encryption import generate_rsa_keys
from certificates.issue import issue_certificate
from certificates.verify import verify_certificate
import sqlite3

app = Flask(__name__)
app.secret_key = "secret123"

import os
from crypto.encryption import generate_rsa_keys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

KEY_FILE_PRIVATE = "private_key.pem"
KEY_FILE_PUBLIC = "public_key.pem"

def load_or_generate_keys():
    if os.path.exists(KEY_FILE_PRIVATE) and os.path.exists(KEY_FILE_PUBLIC):
        print("Loading existing keys...")
        with open(KEY_FILE_PRIVATE, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        with open(KEY_FILE_PUBLIC, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return private_key, public_key
    else:
        print("Generating new keys...")
        private_key, public_key = generate_rsa_keys()
        
        # Save Private Key
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(KEY_FILE_PRIVATE, "wb") as f:
            f.write(pem_private)
            
        # Save Public Key
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(KEY_FILE_PUBLIC, "wb") as f:
            f.write(pem_public)
            
        return private_key, public_key

admin_private_key, admin_public_key = load_or_generate_keys()

def init_db():
    with sqlite3.connect("database.db", timeout=30) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            salt BLOB,
            role TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            encrypted_cert TEXT,
            encrypted_key TEXT,
            signature TEXT,
            issue_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS certificate_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            details TEXT,
            status TEXT DEFAULT 'pending',
            request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """)
        conn.commit()

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]
        
        try:
            totp_secret = register_user(username, password, role)
            # User said "not registering", so we skip the setup screen here
            # and let them set it up during first login (auto-migration).
            return redirect("/")
        except sqlite3.IntegrityError:
            return "Username already exists ❌"
            
    return render_template("register.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    success, role, totp_secret = login_user(username, password)
    if success:
        # Auto-migration: If existing user has no secret, generate one now
        if not totp_secret:
            totp_secret = generate_totp_secret()
            with sqlite3.connect("database.db", timeout=30) as conn:
                conn.execute("UPDATE users SET totp_secret=? WHERE username=?", (totp_secret, username))
                conn.commit()

        session["temp_user"] = {
            "username": username, 
            "role": role,
            "totp_secret": totp_secret
        }
        return redirect("/otp-verify")
    return render_template("login.html", error="Invalid credentials ❌")

@app.route("/otp-verify", methods=["GET", "POST"])
def otp_verify():
    if "temp_user" not in session:
        return redirect("/")

    if request.method == "POST":
        user_otp = request.form["otp"]
        user_data = session.get("temp_user")
        secret = user_data.get("totp_secret")
        
        # Handle case where existing users might not have a secret (migration fallback)
        if not secret:
             # In a real app, force setup. Here, just fail or let them in if we wanted to be insecure (but we won't).
             return "2FA not set up for this user. Please contact admin. ❌"

        if verify_totp(secret, user_otp):
            session.pop("temp_user")
            session["username"] = user_data["username"]
            session["role"] = user_data["role"]
            return redirect("/dashboard")
        return "Invalid Code ❌"

    # GET request - Show form (and QR code for demo convenience)
    user_data = session.get("temp_user")
    username = user_data.get("username")
    secret = user_data.get("totp_secret")
    
    qr_code = None
    if secret:
        uri = get_totp_uri(username, secret)
        qr_code = generate_qr_code(uri)

    return render_template("otp.html", qr_code=qr_code)

@app.route("/dashboard")
def dashboard():
    role = session.get("role")
    username = session.get("username")
    
    students = []
    my_certs = []
    my_requests = []
    pending_requests = []
    all_certs = [] # For verifiers
    
    with sqlite3.connect("database.db", timeout=30) as conn:
        cur = conn.cursor()
        
        if role == "admin":
            cur.execute("SELECT username FROM users WHERE role='student'")
            students = [row[0] for row in cur.fetchall()]
            
            cur.execute("SELECT id, username, details, request_date FROM certificate_requests WHERE status='pending'")
            pending_requests = cur.fetchall()
            
        if role == "student":
            cur.execute("SELECT id FROM users WHERE username=?", (username,))
            user_id = cur.fetchone()[0]
            
            cur.execute("SELECT id, issue_date, encrypted_cert, encrypted_key, signature FROM certificates WHERE user_id=?", (user_id,))
            my_certs = cur.fetchall()
            
            cur.execute("SELECT details, status, request_date FROM certificate_requests WHERE user_id=?", (user_id,))
            my_requests = cur.fetchall()

        if role == "verifier":
            # Fetch ALL certificates with student usernames
            cur.execute("""
                SELECT c.id, u.username, c.issue_date, c.signature 
                FROM certificates c 
                JOIN users u ON c.user_id = u.id
            """)
            all_certs = cur.fetchall()

    return render_template("dashboard.html", role=role, students=students, my_certs=my_certs, my_requests=my_requests, pending_requests=pending_requests, all_certs=all_certs)

@app.route("/issue", methods=["POST"])
def issue():
    if not has_permission(session["role"], "sign_certificate"):
        return "Access Denied ❌"

    text = request.form["text"]
    student_username = request.form.get("student_username")
    
    if not student_username:
        return "Please select a student ⚠️"

    enc_cert, enc_key, signature = issue_certificate(
        text, admin_private_key, admin_public_key
    )
    
    # Save to DB
    with sqlite3.connect("database.db", timeout=30) as conn:
        cur = conn.cursor()
        # Find student ID
        cur.execute("SELECT id FROM users WHERE username=?", (student_username,))
        row = cur.fetchone()
        if not row:
            return "Student not found ❌"
        user_id = row[0]
        
        cur.execute("""
            INSERT INTO certificates (user_id, encrypted_cert, encrypted_key, signature)
            VALUES (?, ?, ?, ?)
        """, (user_id, enc_cert, enc_key, signature))
        conn.commit()

    session["cert"] = (enc_cert, enc_key, signature) # Keep in session for immediate verification demo
    return "Certificate Issued to " + student_username + " ✅"

@app.route("/request_certificate", methods=["POST"])
def request_certificate():
    if session.get("role") != "student":
        return "Access Denied ❌"
        
    details = request.form["details"]
    username = session["username"]
    
    with sqlite3.connect("database.db", timeout=30) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username=?", (username,))
        user_id = cur.fetchone()[0]
        
        cur.execute("""
            INSERT INTO certificate_requests (user_id, username, details)
            VALUES (?, ?, ?)
        """, (user_id, username, details))
        conn.commit()
    
    return redirect("/dashboard")

@app.route("/approve_request/<int:req_id>", methods=["POST"])
def approve_request(req_id):
    if session.get("role") != "admin":
        return "Access Denied ❌"
        
    with sqlite3.connect("database.db", timeout=30) as conn:
        cur = conn.cursor()
        
        # Get request details
        cur.execute("SELECT user_id, username, details FROM certificate_requests WHERE id=?", (req_id,))
        req = cur.fetchone()
        if not req:
            return "Request not found ❌"
            
        user_id, student_username, details = req
        
        # Issue Certificate Logic
        enc_cert, enc_key, signature = issue_certificate(
            details, admin_private_key, admin_public_key
        )
        
        # Save Certificate
        cur.execute("""
            INSERT INTO certificates (user_id, encrypted_cert, encrypted_key, signature)
            VALUES (?, ?, ?, ?)
        """, (user_id, enc_cert, enc_key, signature))
        
        # Update Request Status
        cur.execute("UPDATE certificate_requests SET status='approved' WHERE id=?", (req_id,))
        conn.commit()

        # Populate session for immediate verification "Last Issued"
        session["cert"] = (enc_cert, enc_key, signature)
        
    return redirect("/dashboard")

@app.route("/verify")
@app.route("/verify/<int:cert_id>")
def verify(cert_id=None):
    if not has_permission(session.get("role"), "verify_certificate"):
        return "Access Denied ❌"

    enc_cert = None
    enc_key = None
    signature = None

    if cert_id:
        # Fetch from DB
        with sqlite3.connect("database.db", timeout=30) as conn:
            cur = conn.cursor()
            cur.execute("SELECT encrypted_cert, encrypted_key, signature FROM certificates WHERE id=?", (cert_id,))
            row = cur.fetchone()
            if row:
                enc_cert, enc_key, signature = row
            else:
                return "Certificate ID not found ❌"
    elif "cert" in session:
        # Fallback to session
        enc_cert, enc_key, signature = session["cert"]
    else:
        return "No certificate specified or found in session ⚠️"

    valid, data = verify_certificate(
        enc_cert, enc_key, signature,
        admin_private_key, admin_public_key
    )
    return render_template(
        "verify.html",
        valid=valid,
        data=data,
        enc_cert=enc_cert,
        enc_key=enc_key,
        signature=signature
    )

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
