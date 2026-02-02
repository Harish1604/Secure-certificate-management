"""
Base64 encoding utilities for safe data transmission
"""
import base64
import json


def encode_base64(data):
    """
    Encode bytes to Base64 string
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('utf-8')


def decode_base64(encoded):
    """
    Decode Base64 string to bytes
    """
    return base64.b64decode(encoded)


def encode_metadata(metadata_dict):
    """
    Encode certificate metadata dictionary to Base64
    """
    json_str = json.dumps(metadata_dict)
    return encode_base64(json_str)


def decode_metadata(encoded_metadata):
    """
    Decode Base64 encoded metadata to dictionary
    """
    json_str = decode_base64(encoded_metadata).decode('utf-8')
    return json.loads(json_str)
