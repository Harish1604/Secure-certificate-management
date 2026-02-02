"""
Encryption utilities for AES file encryption and RSA key exchange
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def generate_aes_key():
    """Generate a random 256-bit AES key"""
    return os.urandom(32)  # 256 bits


def encrypt_file_aes(file_data, key):
    """
    Encrypt file data using AES-256 in CBC mode
    Returns: (iv + encrypted_data)
    """
    iv = os.urandom(16)  # 128-bit IV for AES
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Add PKCS7 padding
    padding_length = 16 - (len(file_data) % 16)
    padded_data = file_data + bytes([padding_length] * padding_length)
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return IV + encrypted data
    return iv + encrypted_data


def decrypt_file_aes(encrypted_data, key):
    """
    Decrypt file data using AES-256 in CBC mode
    encrypted_data should be: iv + encrypted_data
    """
    iv = encrypted_data[:16]
    actual_encrypted_data = encrypted_data[16:]
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()
    
    # Remove PKCS7 padding
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]


def encrypt_key_rsa(aes_key, public_key_path):
    """Encrypt AES key using RSA public key"""
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def decrypt_key_rsa(encrypted_key, private_key_path):
    """Decrypt AES key using RSA private key"""
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key
