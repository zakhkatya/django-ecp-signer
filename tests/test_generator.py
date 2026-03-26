from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from ecp_auth.generator import generate_key_and_certificate, generate_p12
from ecp_auth.certificate import CertificateParser


def test_generates_valid_certificate():
    # The returned PEM must be parseable by CertificateParser without errors.
    _, cert_pem = generate_key_and_certificate("1234567890", "Іван Франко")
    assert CertificateParser(cert_pem).is_expired() is False


def test_taxpayer_id_in_certificate():
    _, cert_pem = generate_key_and_certificate("9876543210", "Леся Українка")
    assert CertificateParser(cert_pem).extract_taxpayer_id() == "9876543210"


def test_p12_loadable():
    # The P12 container must be loadable back without a password.
    key, cert_pem = generate_key_and_certificate("1234567890", "Тарас Шевченко")
    p12_bytes = generate_p12(key, cert_pem)
    loaded_key, loaded_cert, _ = pkcs12.load_key_and_certificates(
        p12_bytes, password=None
    )
    assert loaded_cert is not None
    assert loaded_key is not None


def test_private_key_matches_certificate():
    # The public key embedded in the cert must match the returned private key.
    key, cert_pem = generate_key_and_certificate("1234567890", "Іван Мазепа")
    cert = x509.load_pem_x509_certificate(cert_pem)
    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    enc = serialization.Encoding.PEM
    assert cert.public_key().public_bytes(enc, fmt) == key.public_key().public_bytes(
        enc, fmt
    )
