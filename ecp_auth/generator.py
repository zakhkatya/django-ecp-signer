import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


def generate_key_and_certificate(taxpayer_id: str, common_name: str) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generate an EC private key and a self-signed X.509 certificate.

    The certificate embeds the taxpayer ID (РНОКПП) in the serialNumber field,
    which is the format expected by Ukrainian qualified CAs.

    Returns a (private_key, cert_pem) tuple where cert_pem is PEM-encoded bytes.
    """
    key = ec.generate_private_key(ec.SECP256R1())

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            # serialNumber carries the taxpayer ID (РНОКПП) in Ukrainian certs.
            x509.NameAttribute(NameOID.SERIAL_NUMBER, taxpayer_id),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key, cert_pem


def generate_p12(private_key: ec.EllipticCurvePrivateKey, cert_pem: bytes) -> bytes:
    """Pack a private key and certificate into a PKCS#12 (.p12) container.

    The archive is created without a password so it can be loaded directly
    in test environments. Do not use passwordless P12 files in production.

    Returns the raw DER-encoded PKCS#12 bytes.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    return pkcs12.serialize_key_and_certificates(
        name=None,
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )
