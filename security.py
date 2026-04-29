import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from jwcrypto import jwk
from argon2 import PasswordHasher

# environment
_raw = os.environ.get("NOT_MY_KEY", "")
if not _raw:
    raise RuntimeError("NOT_MY_KEY environment variable is not set. please set it before running")
AES_KEY = _raw.encode().ljust(32, b"0")[:32]

# argon2
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=1,
    hash_len=32,
    salt_len=16,
)

# cryptography
def encrypt_private_key(pem: str) -> str:
    """
    encrypts a PEM encoded RSA private key using AES-256-CBC
    generates a secure random IV and pads the data to match the block size
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 padding to block size
    data = pem.encode()
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv.hex() + ":" + ciphertext.hex()

def decrypt_private_key(stored: str) -> str:
    """
    decrypts a stored AES-256-CBC string back to its original PEM format
    extracts the IV and removes the PKCS7 padding after decryption
    """
    try:
        iv_hex, ct_hex = stored.split(":")
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(ct_hex)
        
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # remove PKCS7 padding
        pad_len = data[-1]
        return data[:-pad_len].decode()
    except (ValueError, IndexError) as e:
        raise ValueError("failed to decrypt the private key. data may be corrupted") from e

def generate_rsa_key():
    """generates a secure 2048-bit RSA private key for jwt signing"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def private_pem_to_jwk(pem: str, kid: int) -> dict:
    """converts a decrypted private PEM string into a public jwk dictionary"""
    try:
        key = jwk.JWK.from_pem(pem.encode())
        pub = json.loads(key.export_public())
        pub["kid"] = str(kid)
        pub["use"] = "sig"
        pub["alg"] = "RS256"
        return pub
    except Exception as e:
        # catching generic here only to wrap it in a specific ValueError
        raise ValueError("invalid PEM format provided to jwk converter") from e