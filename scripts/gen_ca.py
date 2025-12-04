"""
Generate a self-signed Root CA certificate.
Usage: python scripts/gen_ca.py --name "FAST-NU Root CA"

"""

import argparse
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_root_ca(ca_name: str, output_dir: Path):
    """
    Generate a self-signed root CA certificate.
    Args:
        ca_name: Common Name for the CA
        output_dir: Directory to save the CA key and certificate
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate RSA private key (2048-bit)
    print(f"[*] Generating RSA private key (2048-bit)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Build certificate subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])
    
    # Create certificate
    print(f"[*] Creating self-signed certificate...")
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    
    # Save private key
    key_path = output_dir / "ca_key.pem"
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
    cert_path = output_dir / "ca_cert.pem"
    print(f"[*] Saving certificate to: {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"\n[✓] Root CA created successfully!")
    print(f"    Private Key: {key_path}")
    print(f"    Certificate: {cert_path}")
    print(f"\n[!] Keep ca_key.pem secure and never commit it to version control!")


def main():
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--name", default="FAST-NU Root CA", help="CA Common Name")
    parser.add_argument("--out", default="certs", help="Output directory")
    
    args = parser.parse_args()
    
    output_dir = Path(args.out)
    generate_root_ca(args.name, output_dir)


if __name__ == "__main__":
    main()