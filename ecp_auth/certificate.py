import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID

from .exceptions import InvalidCertificateError


class CertificateParser:
    """Parses a PEM-encoded X.509 certificate and exposes its metadata.

    Args:
        cert_pem: PEM-encoded certificate bytes.

    Raises:
        InvalidCertificateError: If the certificate cannot be parsed.
    """

    def __init__(self, cert_pem: bytes) -> None:
        try:
            self._cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception as e:
            raise InvalidCertificateError(f"Cannot parse certificate: {e}")

    def is_expired(self) -> bool:
        """Check whether the certificate's validity period has passed.

        Returns:
            True if the current UTC time is past ``not_valid_after``.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        return now > self._cert.not_valid_after_utc

    def get_common_name(self) -> str:
        """Extract the Common Name (CN) from the certificate subject.

        Returns:
            The CN field value as a string.

        Raises:
            InvalidCertificateError: If the CN field is not present.
        """
        attrs = self._cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs:
            raise InvalidCertificateError("Common name not found")
        return str(attrs[0].value)

    def get_organization(self) -> str | None:
        """Extract the Organization (O) from the certificate subject.

        Returns:
            The organization name, or None if the field is absent.
        """
        attrs = self._cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return str(attrs[0].value) if attrs else None

    def to_dict(self) -> dict:
        """Return parsed certificate metadata as a dictionary.

        Returns:
            A dict with keys ``common_name``, ``organization``,
            ``not_valid_before``, and ``not_valid_after`` (ISO 8601 strings).
        """
        return {
            "common_name": self.get_common_name(),
            "organization": self.get_organization(),
            "not_valid_before": self._cert.not_valid_before_utc.isoformat(),
            "not_valid_after": self._cert.not_valid_after_utc.isoformat(),
        }
