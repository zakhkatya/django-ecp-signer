import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from ecp_auth.generator import generate_key_and_certificate, private_key_to_pem
from ecp_auth.certificate import CertificateParser


def test_generates_valid_certificate():
    _, cert_pem = generate_key_and_certificate("testuser")
    assert CertificateParser(cert_pem).is_expired() is False


def test_common_name_in_certificate():
    _, cert_pem = generate_key_and_certificate("john_doe")
    assert CertificateParser(cert_pem).get_common_name() == "john_doe"


def test_private_key_to_pem_unencrypted():
    key, _ = generate_key_and_certificate("testuser")
    pem = private_key_to_pem(key)
    assert pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert pem.strip().endswith("-----END PRIVATE KEY-----")


def test_private_key_to_pem_encrypted():
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key, _ = generate_key_and_certificate("testuser")
    pem = private_key_to_pem(key, password="s3cr3t")
    assert pem.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    # Must be loadable with the correct password
    loaded = load_pem_private_key(pem.encode(), password=b"s3cr3t")
    assert loaded is not None


def test_private_key_to_pem_wrong_password_fails():
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key, _ = generate_key_and_certificate("testuser")
    pem = private_key_to_pem(key, password="correct")
    with pytest.raises(Exception):
        load_pem_private_key(pem.encode(), password=b"wrong")


def test_private_key_matches_certificate():
    key, cert_pem = generate_key_and_certificate("testuser")
    cert = x509.load_pem_x509_certificate(cert_pem)
    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    enc = serialization.Encoding.PEM
    assert cert.public_key().public_bytes(enc, fmt) == key.public_key().public_bytes(enc, fmt)
