"""
Issue client/server certificates signed by the Root CA.
Usage: python scripts/gen_cert.py --cn server.local --out certs/server
"""

import argparse
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def load_ca(ca_dir: Path):
    """Load CA private key and certificate."""
    key_path = ca_dir / "ca_key.pem"
    cert_path = ca_dir / "ca_cert.pem"
    
    with open(key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    with open(cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_key, ca_cert


def generate_certificate(common_name: str, ca_key, ca_cert, output_prefix: Path):
    """
    Generate and sign a certificate for client or server.
    
    Args:
        common_name: CN for the certificate (e.g., "server.local", "client.local")
        ca_key: CA private key for signing
        ca_cert: CA certificate
        output_prefix: Path prefix for output files (e.g., "certs/server")
        
    """
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    
    # Generate RSA private key
    print(f"[*] Generating RSA private key for {common_name}...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Build certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Create certificate signed by CA
    print(f"[*] Creating certificate signed by CA...")
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    
    # Save private key
    key_path = Path(str(output_prefix) + "_key.pem")
    print(f"[*] Saving private key to: {key_path}")
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    # Save certificate
    cert_path = Path(str(output_prefix) + "_cert.pem")
    print(f"[*] Saving certificate to: {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"\n[✓] Certificate created successfully for {common_name}!")
    print(f"    Private Key: {key_path}")
    print(f"    Certificate: {cert_path}")


def main():
    parser = argparse.ArgumentParser(description="Issue certificates signed by Root CA")
    parser.add_argument("--cn", required=True, help="Common Name (e.g., server.local)")
    parser.add_argument("--out", required=True, help="Output prefix (e.g., certs/server)")
    parser.add_argument("--ca-dir", default="certs", help="Directory containing CA files")
    
    args = parser.parse_args()
    
    # Load CA
    print(f"[*] Loading CA from {args.ca_dir}...")
    ca_key, ca_cert = load_ca(Path(args.ca_dir))
    
    # Generate certificate
    generate_certificate(args.cn, ca_key, ca_cert, Path(args.out))


if __name__ == "__main__":
    main()