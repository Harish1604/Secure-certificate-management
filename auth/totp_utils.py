"""
TOTP (Time-based One-Time Password) utilities using Google Authenticator
"""
import pyotp
import qrcode
import io
import base64

def generate_totp_secret():
    """Generate a random base32 secret key"""
    return pyotp.random_base32()

def get_provisioning_uri(username, secret, issuer_name="SecureCertSystem"):
    """Get the provisioning URI for the QR code"""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer_name)

def generate_qr_code(provisioning_uri):
    """
    Generate a QR code derived from the provisioning URI
    Returns a base64 encoded string of the image
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def verify_totp(secret, code):
    """
    Verify a TOTP code against the secret
    """
    if not secret:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
