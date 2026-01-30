import base64

def encode(data: bytes):
    return base64.b64encode(data).decode()

def decode(data: str):
    return base64.b64decode(data)
