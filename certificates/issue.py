from crypto.encryption import (
    generate_aes_key, aes_encrypt,
    rsa_encrypt
)
from crypto.signature import sign_data

from utils.encoding import encode

def issue_certificate(text, admin_private_key, admin_public_key):
    data = text.encode()

    aes_key = generate_aes_key()
    encrypted_cert = aes_encrypt(data, aes_key)
    encrypted_key = rsa_encrypt(aes_key, admin_public_key)

    signature = sign_data(admin_private_key, data)

    return encode(encrypted_cert), encode(encrypted_key), encode(signature)
