import pytest
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID


def make_cert_and_key(common_name: str = "testuser", expired: bool = False, not_yet_valid: bool = False):
    """Generate a self-signed EC certificate for testing.

    Returns a (private_key, cert_pem_bytes) tuple. When expired=True, the
    validity window is placed entirely in the past so expiry checks trigger.
    When not_yet_valid=True, the validity window is placed entirely in the
    future so the not_valid_before check triggers.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)

    if expired:
        not_before = now - datetime.timedelta(days=730)
        not_after = now - datetime.timedelta(days=365)
    elif not_yet_valid:
        not_before = now + datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=366)
    else:
        not_before = now
        not_after = now + datetime.timedelta(days=365)

    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
        )
        .issuer_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
        )
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
