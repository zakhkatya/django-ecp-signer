import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


def generate_key_and_certificate(
    common_name: str,
) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generate an EC private key and a self-signed X.509 certificate.

    Returns a (private_key, cert_pem) tuple where cert_pem is PEM-encoded bytes.
    """
    key = ec.generate_private_key(ec.SECP256R1())

    now = datetime.datetime.now(datetime.timezone.utc)
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
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key, cert_pem


def private_key_to_pem(private_key: ec.EllipticCurvePrivateKey) -> str:
    """Serialize a private key to PEM text (unencrypted)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
