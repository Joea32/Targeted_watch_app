from cryptography.fernet import Fernet
import base64
import os

# Ideally generate this once and store securely (env variable or secrets manager)
# For demo, we generate here (but save the key for real use)
# key = Fernet.generate_key()
# print(key)

# Use a fixed key stored securely in environment variable:
key = os.getenv('ENCRYPTION_KEY')
if not key:
    raise Exception("ENCRYPTION_KEY environment variable not set")

fernet = Fernet(key)

def encrypt(data: str) -> bytes:
    return fernet.encrypt(data.encode())

def decrypt(token: bytes) -> str:
    return fernet.decrypt(token).decode()