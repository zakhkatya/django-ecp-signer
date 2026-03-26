class ECPAuthError(Exception):
    """Base exception for all ECP auth errors."""
    pass


class InvalidSignatureError(ECPAuthError):
    """Raised when signature verification fails."""
    pass


class CertificateExpiredError(ECPAuthError):
    """Raised when certificate is expired."""
    pass


class InvalidCertificateError(ECPAuthError):
    """Raised when certificate format is invalid."""
    pass


class NonceExpiredError(ECPAuthError):
    """Raised when nonce is expired or already used."""
    pass


class NonceNotFoundError(ECPAuthError):
    """Raised when nonce does not exist."""
    pass
