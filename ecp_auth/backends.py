import logging
from typing import Any

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.http import HttpRequest

from .models import ECPNonce, ECPCertificate
from .validators import SignatureValidator
from .certificate import CertificateParser
from .exceptions import (
    NonceNotFoundError,
    NonceExpiredError,
    InvalidSignatureError,
    InvalidCertificateError,
    CertificateExpiredError,
)

logger = logging.getLogger(__name__)

User = get_user_model()


class ECPAuthenticationBackend(ModelBackend):
    """Django authentication backend that verifies ECDSA digital signatures.

    Intended to be used alongside the standard ``ModelBackend``. The password
    check is handled by ``ECPLoginMixin`` before this backend is called.
    """

    def authenticate(
        self,
        request: HttpRequest | None,
        signature: bytes | None = None,
        username: str | None = None,
        nonce_id: int | None = None,
        **kwargs: Any,
    ) -> Any | None:
        """Authenticate a user by verifying their ECDSA signature.

        Args:
            request: The current HTTP request (may be None in tests).
            signature: DER-encoded ECDSA signature of the nonce value.
            username: The username whose certificate will be used for verification.
            nonce_id: Primary key of the ``ECPNonce`` that was signed.
            **kwargs: Ignored extra keyword arguments (Django convention).

        Returns:
            The authenticated ``User`` instance on success, or ``None`` if
            any verification step fails.
        """
        if not (signature and username and nonce_id):
            return None
        try:
            nonce = self._get_nonce(nonce_id)
            user = self._get_user(username)
            cert = self._get_certificate(user)
            cert_pem = cert.certificate_pem.encode()
            self._check_expired(cert_pem)
            self._verify_signature(nonce, signature, cert_pem)
            nonce.consume()
            return user
        except (
            NonceNotFoundError,
            NonceExpiredError,
            InvalidSignatureError,
            InvalidCertificateError,
            CertificateExpiredError,
        ) as exc:
            logger.warning("ECP authentication failed for username=%s: %s", username, exc)
            return None

    def _get_nonce(self, nonce_id: int) -> ECPNonce:
        """Fetch and validate a nonce by primary key.

        Args:
            nonce_id: Primary key of the nonce.

        Returns:
            A valid, unused ``ECPNonce`` instance.

        Raises:
            NonceNotFoundError: If no nonce with the given ID exists.
            NonceExpiredError: If the nonce has already been used or has expired.
        """
        try:
            nonce = ECPNonce.objects.get(pk=nonce_id)
        except ECPNonce.DoesNotExist:
            raise NonceNotFoundError(f"Nonce not found: {nonce_id}")
        if not nonce.is_valid():
            raise NonceExpiredError("Nonce is expired or already used")
        return nonce

    def _get_user(self, username: str) -> Any:
        """Look up a user by username.

        Args:
            username: The username to look up.

        Returns:
            The matching ``User`` instance.

        Raises:
            InvalidCertificateError: If no user with that username exists.
        """
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            raise InvalidCertificateError(f"No user found: {username}")

    def _get_certificate(self, user: Any) -> ECPCertificate:
        """Fetch the stored public certificate for a user.

        Args:
            user: The ``User`` instance whose certificate to retrieve.

        Returns:
            The associated ``ECPCertificate`` instance.

        Raises:
            InvalidCertificateError: If no certificate is registered for the user.
        """
        try:
            return ECPCertificate.objects.get(user=user)
        except ECPCertificate.DoesNotExist:
            raise InvalidCertificateError(f"No certificate for user: {user.username}")

    def _verify_signature(
        self, nonce: ECPNonce, signature: bytes, cert_pem: bytes
    ) -> None:
        """Verify the ECDSA signature against the nonce value.

        Args:
            nonce: The nonce whose value was signed.
            signature: DER-encoded ECDSA signature bytes.
            cert_pem: PEM-encoded certificate containing the public key.

        Raises:
            InvalidSignatureError: If verification fails.
        """
        SignatureValidator().verify(nonce.value.encode(), signature, cert_pem)

    def _check_expired(self, cert_pem: bytes) -> None:
        """Check that the certificate has not expired.

        Args:
            cert_pem: PEM-encoded certificate bytes.

        Raises:
            CertificateExpiredError: If the certificate validity period has passed.
        """
        if CertificateParser(cert_pem).is_expired():
            raise CertificateExpiredError("Certificate is expired")
