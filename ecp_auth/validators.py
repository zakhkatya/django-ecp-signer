from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .exceptions import InvalidCertificateError, InvalidSignatureError


class SignatureValidator:
    """Verifies ECDSA digital signatures against X.509 certificates."""

    def verify(
        self,
        data: bytes,
        signature: bytes,
        cert_pem: bytes,
    ) -> bool:
        """Verify that ``signature`` was produced by the private key in ``cert_pem``.

        Args:
            data: The original data that was signed (e.g. nonce bytes).
            signature: DER-encoded ECDSA signature bytes.
            cert_pem: PEM-encoded X.509 certificate containing the public key.

        Returns:
            True if the signature is valid.

        Raises:
            InvalidCertificateError: If the certificate cannot be loaded or
                does not contain an ECDSA public key.
            InvalidSignatureError: If signature verification fails or the
                signature bytes are malformed.

        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception as e:
            raise InvalidCertificateError(f"Cannot load certificate: {e}")

        public_key = cert.public_key()

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise InvalidCertificateError("Certificate must contain ECDSA public key")

        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise InvalidSignatureError("Signature verification failed")
        except Exception as e:
            raise InvalidSignatureError(f"Unexpected error during verification: {e}")
        else:
            return True
