"""
AES-128 encryption/decryption with PKCS#7 padding.
Using ECB mode as specified (note: ECB is generally insecure but used per assignment spec).
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def pkcs7_pad(data: bytes, block_size: int = 128) -> bytes:
    """
    Apply PKCS#7 padding to data.
    Args:
        data: Data to pad
        block_size: Block size in bits (default: 128 for AES)
    
    Returns:
        Padded data
    """
    padder = padding.PKCS7(block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def pkcs7_unpad(padded_data: bytes, block_size: int = 128) -> bytes:
    """
    Remove PKCS#7 padding from data.
    
    Args:
        padded_data: Padded data
        block_size: Block size in bits (default: 128 for AES)
    
    Returns:
        Unpadded data
    """
    unpadder = padding.PKCS7(block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-128-ECB with PKCS#7 padding.
    
    Args:
        plaintext: Data to encrypt
        key: 16-byte AES key
    
    Returns:
        Ciphertext
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Apply PKCS#7 padding
    padded_plaintext = pkcs7_pad(plaintext)
    
    # Create AES cipher in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    
    # Encrypt
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES-128-ECB and remove PKCS#7 padding.
    
    Args:
        ciphertext: Data to decrypt
        key: 16-byte AES key
    
    Returns:
        Plaintext
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Create AES cipher in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    
    # Decrypt
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext


def encrypt_message(message: str, key: bytes) -> bytes:
    """
    Encrypt a text message.
    Args:
        message: Text message to encrypt
        key: 16-byte AES key
    
    Returns:
        Ciphertext
    """
    plaintext = message.encode('utf-8')
    return aes_encrypt(plaintext, key)


def decrypt_message(ciphertext: bytes, key: bytes) -> str:
    """
    Decrypt a ciphertext to text message.
    Args:
        ciphertext: Encrypted data
        key: 16-byte AES key
    
    Returns:
        Decrypted text message
    """
    plaintext = aes_decrypt(ciphertext, key)
    return plaintext.decode('utf-8')