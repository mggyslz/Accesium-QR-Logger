# core/security.py
import os
import hashlib
import binascii
from config.settings import PBKDF2_ITERATIONS, PBKDF2_ALGO, SALT_BYTES

def generate_salt() -> str:
    return binascii.hexlify(os.urandom(SALT_BYTES)).decode()

def hash_pin(pin: str, salt: str) -> str:
    """
    Hashes the pin with PBKDF2 HMAC and returns hex digest.
    """
    if isinstance(pin, str):
        pin = pin.encode("utf-8")
    salt_bytes = binascii.unhexlify(salt)
    dk = hashlib.pbkdf2_hmac(PBKDF2_ALGO, pin, salt_bytes, PBKDF2_ITERATIONS)
    return binascii.hexlify(dk).decode()

def verify_pin(pin: str, salt: str, expected_hash: str) -> bool:
    return hash_pin(pin, salt) == expected_hash
