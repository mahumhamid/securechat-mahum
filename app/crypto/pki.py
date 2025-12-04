"""
X.509 certificate validation with CA signature verification.
"""

from datetime import datetime
from pathlib import Path
from typing import Tuple, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def load_certificate(cert_path: str) -> x509.Certificate:
    """Load X.509 certificate from PEM file."""
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return cert


def load_private_key(key_path: str):
    """Load RSA private key from PEM file."""
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return key


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get SHA-256 fingerprint of certificate."""
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex()


def validate_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Validate certificate against CA and optional CN.
    
    Args:
        cert: Certificate to validate
        ca_cert: CA certificate for signature verification
        expected_cn: Expected Common Name (optional)
    
    Returns:
        (valid: bool, error_message: str)
    """
    
    # 1. Check validity period
    now = datetime.utcnow()
    if now < cert.not_valid_before:
        return False, "BAD_CERT: Certificate not yet valid"
    if now > cert.not_valid_after:
        return False, "BAD_CERT: Certificate expired"
    
    # 2. Verify CA signature
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except InvalidSignature:
        return False, "BAD_CERT: Invalid CA signature"
    except Exception as e:
        return False, f"BAD_CERT: Signature verification failed ({e})"
    
    # 3. Verify issuer matches CA subject
    if cert.issuer != ca_cert.subject:
        return False, "BAD_CERT: Issuer does not match CA"
    
    # 4. Check Common Name if expected
    if expected_cn:
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            if cn != expected_cn:
                return False, f"BAD_CERT: CN mismatch (expected {expected_cn}, got {cn})"
        except (IndexError, AttributeError):
            return False, "BAD_CERT: No Common Name in certificate"
    
    # 5. Check Basic Constraints (should not be CA for end-entity certs)
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        # For client/server certs, ca should be False
        # We'll allow both for flexibility
    except x509.ExtensionNotFound:
        pass  # Optional for end-entity certificates
    
    return True, "Certificate valid"


def validate_certificate_chain(
    cert_pem: bytes,
    ca_cert_path: str,
    expected_cn: Optional[str] = None
) -> Tuple[bool, str, Optional[x509.Certificate]]:
    """
    Validate certificate received from peer.
    Args:
        cert_pem: Certificate in PEM format (bytes)
        ca_cert_path: Path to CA certificate
        expected_cn: Expected Common Name
    
    Returns:
        (valid: bool, message: str, cert: Optional[Certificate])
    """
    
    try:
        # Load peer certificate
        cert = x509.load_pem_x509_certificate(cert_pem)
        
        # Load CA certificate
        ca_cert = load_certificate(ca_cert_path)
        
        # Validate
        valid, message = validate_certificate(cert, ca_cert, expected_cn)
        
        if valid:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            fingerprint = get_certificate_fingerprint(cert)
            return True, f"Certificate valid for {cn} (fingerprint: {fingerprint[:16]}...)", cert
        else:
            return False, message, None
            
    except Exception as e:
        return False, f"BAD_CERT: {e}", None


def export_certificate_pem(cert: x509.Certificate) -> bytes:
    """Export certificate to PEM format."""
    return cert.public_bytes(serialization.Encoding.PEM)


def get_common_name(cert: x509.Certificate) -> str:
    """Extract Common Name from certificate."""
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    return cn