# python_client/security_ops_py.py
import os
import binascii # For hex conversion

def derive_key_from_pin_py(pin: str, salt: str, length: int) -> bytes:
    """
    'Hashes' a PIN by appending a salt and taking a substring.
    MUST match the C++ server's derive_key_from_pin logic.
    """
    combined = salt + pin
    if len(combined) < length:
        combined = combined.ljust(length, '0') # Pad if too short
    return combined[:length].encode('utf-8')

def xor_encrypt_decrypt_py(data: bytes, key: bytes) -> bytes:
    """Performs XOR encryption/decryption."""
    if not key: return data
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def bytes_to_hex_py(data_bytes: bytes) -> str:
    return binascii.hexlify(data_bytes).decode('utf-8')

def hex_to_bytes_py(hex_str: str) -> bytes:
    return binascii.unhexlify(hex_str)

def calculate_checksum_py(data: bytes) -> int:
    """Calculates a simple checksum, must match C++ server's logic."""
    current_sum = 0
    for byte_val in data:
        current_sum = (current_sum + byte_val) % 4294967295 # Modulo a large prime (or 2^32)
    return current_sum