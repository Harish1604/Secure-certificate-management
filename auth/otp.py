import pyotp
import qrcode
import io
import base64

def generate_totp_secret():
    return pyotp.random_base32()

def get_totp_uri(username, secret):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureCerts")

def generate_qr_code(uri):
    # Ensure high contrast: Black QR on White Background
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

def verify_totp(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
