"""
Certificate verification module
Handles decryption and signature verification
"""
from crypto.encryption import decrypt_key_rsa, decrypt_file_aes
from crypto.signature import verify_signature
from crypto.hash_utils import hash_file
from utils.encoding import decode_base64


def verify_certificate(certificate_data, private_key_path, public_key_path):
    """
    Verify a certificate's authenticity
    
    Process:
    1. Decrypt AES key using RSA private key
    2. Decrypt certificate using AES key
    3. Recalculate SHA-256 hash
    4. Verify signature using RSA public key
    
    Returns: {
        'valid': True/False,
        'decrypted_file': bytes (if valid),
        'message': str
    }
    """
    try:
        # Extract data
        encrypted_file = certificate_data['encrypted_file']
        encrypted_key_b64 = certificate_data['encrypted_key']
        signature_b64 = certificate_data['digital_signature']
        stored_hash = certificate_data['file_hash']
        
        # Decode from Base64
        encrypted_key = decode_base64(encrypted_key_b64)
        signature = decode_base64(signature_b64)
        
        # Step 1: Decrypt AES key using RSA
        aes_key = decrypt_key_rsa(encrypted_key, private_key_path)
        
        # Step 2: Decrypt certificate using AES
        decrypted_file = decrypt_file_aes(encrypted_file, aes_key)
        
        # Step 3: Recalculate hash
        calculated_hash = hash_file(encrypted_file)
        
        # Step 4: Verify signature
        signature_valid = verify_signature(
            calculated_hash.encode('utf-8'),
            signature,
            public_key_path
        )
        
        # Check if hash matches
        hash_matches = (calculated_hash == stored_hash)
        
        if signature_valid and hash_matches:
            return {
                'valid': True,
                'decrypted_file': decrypted_file,
                'message': 'VALID - Certificate is authentic and untampered',
                'crypto_details': {
                    'encrypted_key_b64': encrypted_key_b64,
                    'signature_b64': signature_b64,
                    'stored_hash': stored_hash,
                    'calculated_hash': calculated_hash,
                    'aes_key_hex': aes_key.hex()
                }
            }
        else:
            return {
                'valid': False,
                'decrypted_file': None,
                'message': 'TAMPERED - Certificate has been modified or signature is invalid',
                'crypto_details': {
                    'encrypted_key_b64': encrypted_key_b64,
                    'signature_b64': signature_b64,
                    'stored_hash': stored_hash,
                    'calculated_hash': calculated_hash,
                    'aes_key_hex': aes_key.hex() if aes_key else None
                }
            }
    
    except Exception as e:
        return {
            'valid': False,
            'decrypted_file': None,
            'message': f'ERROR - Verification failed: {str(e)}'
        }


def verify_certificate_by_id(certificate_id, private_key_path, public_key_path):
    """
    Verify a certificate from database by ID
    """
    from certificates.issue import get_certificate_by_id
    
    cert_data = get_certificate_by_id(certificate_id)
    
    if not cert_data:
        return {
            'valid': False,
            'decrypted_file': None,
            'message': 'ERROR - Certificate not found'
        }
    
    result = verify_certificate(cert_data, private_key_path, public_key_path)
    
    # Enrich result with certificate metadata
    result['owner_id'] = cert_data.get('owner_id')
    result['certificate_id'] = cert_data.get('id')
    
    # Flatten crypto details for easier template access
    if 'crypto_details' in result:
        result['encrypted_key'] = result['crypto_details']['encrypted_key_b64']
        result['digital_signature'] = result['crypto_details']['signature_b64']
        result['file_hash'] = result['crypto_details']['stored_hash']
        
    return result
