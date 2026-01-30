from crypto.encryption import aes_decrypt, rsa_decrypt
from crypto.signature import verify_signature

from utils.encoding import decode

def verify_certificate(enc_cert_b64, enc_key_b64, signature_b64, admin_private_key, admin_public_key):
    print("\n[DEMO LOG] --- STARTING CERTIFICATE VERIFICATION ---")
    print("[DEMO LOG] 📥 Decoding Base64 artifacts...")
    enc_cert = decode(enc_cert_b64)
    enc_key = decode(enc_key_b64)
    signature = decode(signature_b64)

    print("[DEMO LOG] 🔓 Recovering Symmetric Key...")
    aes_key = rsa_decrypt(enc_key, admin_private_key)
    
    print("[DEMO LOG] 🔓 Decrypting Certificate Content...")
    cert_data = aes_decrypt(enc_cert, aes_key)
    print(f"[DEMO LOG] 📄 Decrypted Data: {cert_data.decode()}")

    valid = verify_signature(admin_public_key, signature, cert_data)
    print("[DEMO LOG] --- VERIFICATION COMPLETE ---\n")
    return valid, cert_data.decode()
