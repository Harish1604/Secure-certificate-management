import sqlite3
from auth.login import login_user

username = "admin1"
password = "password" # Assume this is what the user used? Or I should try to register a NEW user to be sure.

print("--- Testing Registration & Login Logic ---")
from auth.register import register_user
import time

test_user = f"test_user_{int(time.time())}"
test_pass = "test_pass"

print(f"Registering {test_user}...")
try:
    register_user(test_user, test_pass, "student")
    print("Registration successful (no error raised).")
except Exception as e:
    print(f"Registration failed: {e}")

print(f"Attempting login for {test_user}...")
try:
    success, role = login_user(test_user, test_pass)
    if success:
        print(f"Login SUCCESS. Role: {role}")
    else:
        print("Login FAILED.")
except Exception as e:
    print(f"Login raised exception: {e}")

print("\n--- checking database content for this user ---")
conn = sqlite3.connect("database.db")
c = conn.cursor()
c.execute("SELECT username, hex(salt), password_hash FROM users WHERE username=?", (test_user,))
row = c.fetchone()
if row:
    print(f"User found: {row}")
else:
    print("User NOT found in DB.")
conn.close()
