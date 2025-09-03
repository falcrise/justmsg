import os
import asyncio
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(salt, password):
    """Derive a 256-bit key using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        info=b'secure-chat-key',
        backend=default_backend()
    )
    return hkdf.derive(password.encode())

def encrypt(key, plaintext):
    """Encrypt a message using AES-GCM."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext

def decrypt(key, ciphertext):
    """Decrypt a message using AES-GCM."""
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    encrypted_data = ciphertext[12:]
    try:
        plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
        return plaintext.decode()
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None
