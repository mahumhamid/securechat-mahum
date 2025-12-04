"""
RSA SHA-256 signature generation and verification (PKCS#1 v1.5).
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography import x509


def sign_data(data: bytes, private_key) -> bytes:
    """
    Sign data using RSA-SHA256 (PKCS#1 v1.5).
    
    Args:
        data: Data to sign
        private_key: RSA private key
    
    Returns:
        Signature bytes
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def verify_signature(data: bytes, signature: bytes, certificate: x509.Certificate) -> bool:
    """
    Verify RSA-SHA256 signature using certificate's public key.
    
    Args:
        data: Original data that was signed
        signature: Signature to verify
        certificate: Certificate containing public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key = certificate.public_key()
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"[✗] Signature verification error: {e}")
        return False


def sign_message_digest(digest: bytes, private_key) -> bytes:
    """
    Sign a pre-computed digest (for efficiency).
    Note: For message signing, compute SHA-256 first, then sign that digest.
    
    Args:
        digest: SHA-256 digest (32 bytes)
        private_key: RSA private key
    
    Returns:
        Signature bytes
    """
    return sign_data(digest, private_key)


def verify_message_digest(digest: bytes, signature: bytes, certificate: x509.Certificate) -> bool:
    """
    Verify signature over a pre-computed digest.
    Args:
        digest: SHA-256 digest (32 bytes)
        signature: Signature to verify
        certificate: Certificate containing public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    return verify_signature(digest, signature, certificate)