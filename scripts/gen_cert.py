"""
Issue client/server certificates signed by the Root CA.
Usage:
    python scripts/gen_cert.py --cn server.local --out certs/server
"""

import argparse
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def load_ca(ca_directory: Path):
    """Loads the CA private key and CA certificate."""
    
    ca_key_path = ca_directory / "ca_key.pem"
    ca_cert_path = ca_directory / "ca_cert.pem"

    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(ca_cert_path, "rb") as f:
        ca_certificate = x509.load_pem_x509_certificate(f.read())

    return ca_private_key, ca_certificate


def generate_certificate(common_name: str, ca_key, ca_cert, output_prefix: Path):
    """
    Creates an RSA keypair and issues an X.509 certificate
    signed by Mahum's Root CA.
    """
    output_prefix.parent.mkdir(parents=True, exist_ok=True)

    # --------------------------
    # Generate entity key
    # --------------------------
    print(f"[*] Generating RSA private key for {common_name}...")
    entity_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # --------------------------
    # Certificate subject
    # --------------------------
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "ICT"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # --------------------------
    # Build signed certificate
    # --------------------------
    print(f"[*] Creating certificate for {common_name}...")

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(entity_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
            ]),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    # --------------------------
    # Save outputs
    # --------------------------
    key_path = Path(str(output_prefix) + "_key.pem")
    cert_path = Path(str(output_prefix) + "_cert.pem")

    print(f"[*] Saving private key → {key_path}")
    with open(key_path, "wb") as f:
        f.write(
            entity_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    print(f"[*] Saving certificate → {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"\n[✓] Certificate generated for {common_name}")
    print(f"    Key File       : {key_path}")
    print(f"    Certificate    : {cert_path}\n")


def main():
    parser = argparse.ArgumentParser(description="Generate certificates signed by Root CA")
    parser.add_argument("--cn", required=True, help="Common Name (CN)")
    parser.add_argument("--out", required=True, help="Output prefix path (e.g., certs/server)")
    parser.add_argument("--ca-dir", default="certs", help="Directory where CA files exist")
    args = parser.parse_args()

    print(f"[*] Loading CA from: {args.ca_dir}")
    ca_key, ca_cert = load_ca(Path(args.ca_dir))

    generate_certificate(args.cn, ca_key, ca_cert, Path(args.out))


if __name__ == "__main__":
    main()
