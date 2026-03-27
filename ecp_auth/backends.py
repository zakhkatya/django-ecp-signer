import logging

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

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

    def authenticate(self, request, signature=None, username=None, nonce_id=None, **kwargs):
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
        try:
            nonce = ECPNonce.objects.get(pk=nonce_id)
        except ECPNonce.DoesNotExist:
            raise NonceNotFoundError(f"Nonce not found: {nonce_id}")
        if not nonce.is_valid():
            raise NonceExpiredError("Nonce is expired or already used")
        return nonce

    def _get_user(self, username: str):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            raise InvalidCertificateError(f"No user found: {username}")

    def _get_certificate(self, user) -> ECPCertificate:
        try:
            return ECPCertificate.objects.get(user=user)
        except ECPCertificate.DoesNotExist:
            raise InvalidCertificateError(f"No certificate for user: {user.username}")

    def _verify_signature(self, nonce: ECPNonce, signature: bytes, cert_pem: bytes) -> None:
        SignatureValidator().verify(nonce.value.encode(), signature, cert_pem)

    def _check_expired(self, cert_pem: bytes) -> None:
        if CertificateParser(cert_pem).is_expired():
            raise CertificateExpiredError("Certificate is expired")
