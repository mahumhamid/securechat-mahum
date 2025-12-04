"""
Generate a self-signed Root CA certificate.
Usage:
    python scripts/gen_ca.py --name "SecureChat Root CA"
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
    Builds a 2048-bit RSA keypair and creates a self-signed
    X.509 Root CA certificate for Mahum's SecureChat system.
    """

    output_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Creating 2048-bit RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # ---------------------------------------------------------
    # Create certificate subject + issuer (same for self-signed)
    # ---------------------------------------------------------
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "FAST Campus"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])

    print("[*] Building X.509 certificate...")

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

    # ---------------------------------------------------------
    # Save key + certificate
    # ---------------------------------------------------------
    key_path = output_dir / "ca_key.pem"
    cert_path = output_dir / "ca_cert.pem"

    print(f"[*] Writing private key → {key_path}")
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print(f"[*] Writing certificate → {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print("\n[✓] Root CA created successfully!")
    print("    Private Key : ca_key.pem  (KEEP SECRET!)")
    print("    Certificate : ca_cert.pem\n")


def main():
    parser = argparse.ArgumentParser(description="Root CA Generator")
    parser.add_argument("--name", default="SecureChat Root CA", help="Common Name (CN) of the CA")
    parser.add_argument("--out", default="certs", help="Where to store generated files")
    args = parser.parse_args()

    generate_root_ca(args.name, Path(args.out))


if __name__ == "__main__":
    main()
