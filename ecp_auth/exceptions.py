class ECPAuthError(Exception):
    """Base exception for all ECP authentication errors.

    Catch this class to handle any failure from the ECP auth package,
    or use the specific subclasses for finer-grained error handling.
    """


class InvalidSignatureError(ECPAuthError):
    """Raised when ECDSA signature verification fails.

    This can mean the signature was produced by a different key, the data
    was tampered with, or the signature bytes are malformed.
    """


class CertificateExpiredError(ECPAuthError):
    """Raised when the user's X.509 certificate has passed its validity period."""


class InvalidCertificateError(ECPAuthError):
    """Raised when the certificate cannot be parsed or has an unexpected format.

    Also raised when no certificate is found in the database for a given user.
    """


class NonceExpiredError(ECPAuthError):
    """Raised when the nonce has already been used or its TTL has elapsed."""


class NonceNotFoundError(ECPAuthError):
    """Raised when no nonce with the given identifier exists in the database."""
