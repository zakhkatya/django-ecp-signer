from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
from .exceptions import InvalidCertificateError


class CertificateParser:
    """Parses X.509 certificate and extracts user identity data."""

    def __init__(self, cert_pem: bytes) -> None:
        try:
            self._cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception as e:
            raise InvalidCertificateError(f"Cannot parse certificate: {e}")

    def extract_taxpayer_id(self) -> str:
        """Extracts РНОКПП from certificate Subject serialNumber field."""
        attrs = self._cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        if attrs:
            # Ukrainian qualified certificates may prefix the number with
            # "РНОКПП" or the older "ІПН" label — strip both variants.
            # Cast to str: cryptography types .value as bytes | str, but DN
            # string attributes are always str at runtime.
            value = str(attrs[0].value).replace("РНОКПП", "").replace("ІПН", "").strip()
            # A valid Ukrainian taxpayer ID is exactly 10 digits.
            if value.isdigit() and len(value) == 10:
                return value
        raise InvalidCertificateError("Taxpayer ID not found in certificate")

    def is_expired(self) -> bool:
        """Returns True if certificate validity period has passed."""
        now = datetime.datetime.now(datetime.timezone.utc)
        return now > self._cert.not_valid_after_utc

    def get_common_name(self) -> str:
        """Returns full name from certificate CN field."""
        attrs = self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs:
            raise InvalidCertificateError("Common name not found")
        return str(attrs[0].value)

    def get_organization(self) -> str | None:
        """Returns organization name if present."""
        attrs = self._cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return str(attrs[0].value) if attrs else None

    def to_dict(self) -> dict:
        """Returns parsed certificate data as dictionary."""
        return {
            "taxpayer_id": self.extract_taxpayer_id(),
            "common_name": self.get_common_name(),
            "organization": self.get_organization(),
            "not_valid_before": self._cert.not_valid_before_utc.isoformat(),
            "not_valid_after": self._cert.not_valid_after_utc.isoformat(),
        }
