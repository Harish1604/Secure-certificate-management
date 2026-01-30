from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def sign_data(private_key, data: bytes):
    print("[DEMO LOG] ✍️  Digitally Signing Data (SHA256 + RSA Private Key)...")
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key, signature: bytes, data: bytes):
    print("[DEMO LOG] 🔍 Verifying Digital Signature (SHA256 + RSA Public Key)...")
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[DEMO LOG] ✅ Signature Validated!")
        return True
    except:
        print("[DEMO LOG] ❌ Signature Verification FAILED!")
        return False
