from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from .exceptions import InvalidSignatureError, InvalidCertificateError


class SignatureValidator:
    """Verifies ECDSA digital signatures against X.509 certificates."""

    def verify(
        self,
        data: bytes,
        signature: bytes,
        cert_pem: bytes,
    ) -> bool:
        """
        Verifies that signature was created by the private key
        corresponding to the public key in the certificate.

        Args:
            data: Original data that was signed (nonce bytes).
            signature: DER-encoded signature bytes.
            cert_pem: PEM-encoded X.509 certificate.
        Returns:
            True if signature is valid.
        Raises:
            InvalidSignatureError: If verification fails.
            InvalidCertificateError: If certificate format is wrong.
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception as e:
            raise InvalidCertificateError(f"Cannot load certificate: {e}")

        public_key = cert.public_key()

        # Reject RSA or other key types — only ECDSA is supported.
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise InvalidCertificateError("Certificate must contain ECDSA public key")

        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            raise InvalidSignatureError("Signature verification failed")
        except Exception as e:
            # Catches malformed DER encoding and other low-level errors that
            # don't surface as InvalidSignature but still mean bad input.
            raise InvalidSignatureError(f"Unexpected error: {e}")
