from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def generate_rsa_keys():
    print("[DEMO LOG] 🔑 Generating RSA Keypair (2048-bit)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()

def generate_aes_key():
    key = Fernet.generate_key()
    print(f"[DEMO LOG] 🗝️ Generated AES Symmetric Key: {key.decode()[:10]}... (hidden)")
    return key

def aes_encrypt(data: bytes, key: bytes):
    print("[DEMO LOG] 🔒 AES Encrypting data...")
    return Fernet(key).encrypt(data)

def aes_decrypt(token: bytes, key: bytes):
    print("[DEMO LOG] 🔓 AES Decrypting data...")
    return Fernet(key).decrypt(token)

def rsa_encrypt(key: bytes, public_key):
    print("[DEMO LOG] 🛡️ RSA Encrypting AES Key (Key Exchange)...")
    return public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(enc_key: bytes, private_key):
    print("[DEMO LOG] 🛡️ RSA Decrypting AES Key...")
    return private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
