import pytest
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID


def make_cert_and_key(taxpayer_id: str = "1234567890", expired: bool = False):
    """Generate a self-signed EC certificate for testing.

    Returns a (private_key, cert_pem_bytes) tuple. When expired=True, the
    validity window is placed entirely in the past so expiry checks trigger.
    """
    # SECP256R1 (P-256) mirrors the curve used by Ukrainian qualified CAs.
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)

    if expired:
        # Place the validity window 730–365 days in the past so the cert is
        # already expired at the moment it is created.
        not_before = now - datetime.timedelta(days=730)
        not_after = now - datetime.timedelta(days=365)
    else:
        not_before = now
        not_after = now + datetime.timedelta(days=365)

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Тестовий Користувач"),
            # serialNumber carries the taxpayer ID (РНОКПП) in Ukrainian certs.
            x509.NameAttribute(NameOID.SERIAL_NUMBER, taxpayer_id),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key, cert_pem


@pytest.fixture
def valid_cert_and_key():
    return make_cert_and_key()


@pytest.fixture
def expired_cert_and_key():
    return make_cert_and_key(expired=True)
