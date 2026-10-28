#!/usr/bin/env python3
"""
SealArena mTLS Certificate Generator
Generates Root CA and certificates for Arbiter, Red Runner, and Blue Runner.
"""

import os
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import ipaddress

CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"

def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def save_key(key, filename):
    with open(filename, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

def save_cert(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def build_certs():
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[*] Generating mTLS certificates in {CERTS_DIR}...")

    # 1. Root CA
    ca_key = generate_key()
    save_key(ca_key, CERTS_DIR / "ca.key")

    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SealArena Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SealArena Security"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Infrastructure PKI")
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    save_cert(ca_cert, CERTS_DIR / "ca.crt")
    print("  [+] Generated Root CA (ca.crt, ca.key)")

    # Helper for issuing entity certs
    def issue_cert(common_name, san_dns_list, is_server=True):
        key = generate_key()
        save_key(key, CERTS_DIR / f"{common_name}.key")

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SealArena Security"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Tenant Sandbox")
        ])

        sans = [x509.DNSName(dns) for dns in san_dns_list]
        sans.append(x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")))

        usages = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH] if is_server else [ExtendedKeyUsageOID.CLIENT_AUTH]

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=180))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage(usages), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        save_cert(cert, CERTS_DIR / f"{common_name}.crt")
        print(f"  [+] Generated {common_name} cert ({common_name}.crt, {common_name}.key)")

    # 2. Arbiter Server Cert
    issue_cert("arbiter", ["arbiter", "localhost", "sealarena-arbiter"], is_server=True)

    # 3. Red Client Cert
    issue_cert("red", ["red", "red-runner"], is_server=False)

    # 4. Blue Client Cert
    issue_cert("blue", ["blue", "blue-runner"], is_server=False)

    print("[*] mTLS Certificate Generation Complete.")

if __name__ == "__main__":
    build_certs()
