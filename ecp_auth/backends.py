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

User = get_user_model()


class ECPAuthenticationBackend(ModelBackend):

    def authenticate(self, request, signature=None, taxpayer_id=None, nonce_id=None, **kwargs):
        if not (signature and taxpayer_id and nonce_id):
            return None
        try:
            nonce = self._get_nonce(nonce_id)
            cert = self._get_certificate(taxpayer_id)
            cert_pem = cert.certificate_pem.encode()
            self._check_expired(cert_pem)
            self._verify_signature(nonce, signature, cert_pem)
            nonce.consume()
            return self._get_user(cert)
        except (
            NonceNotFoundError,
            NonceExpiredError,
            InvalidSignatureError,
            InvalidCertificateError,
            CertificateExpiredError,
        ):
            return None

    def _get_nonce(self, nonce_id: str) -> ECPNonce:
        try:
            nonce = ECPNonce.objects.get(value=nonce_id)
        except ECPNonce.DoesNotExist:
            raise NonceNotFoundError(f"Nonce not found: {nonce_id}")
        if not nonce.is_valid():
            raise NonceExpiredError("Nonce is expired or already used")
        return nonce

    def _get_certificate(self, taxpayer_id: str) -> ECPCertificate:
        try:
            return ECPCertificate.objects.get(taxpayer_id=taxpayer_id)
        except ECPCertificate.DoesNotExist:
            raise InvalidCertificateError(
                f"No certificate registered for taxpayer_id: {taxpayer_id}"
            )

    def _verify_signature(self, nonce: ECPNonce, signature: bytes, cert_pem: bytes) -> None:
        SignatureValidator().verify(nonce.value.encode(), signature, cert_pem)

    def _check_expired(self, cert_pem: bytes) -> None:
        if CertificateParser(cert_pem).is_expired():
            raise CertificateExpiredError("Certificate is expired")

    def _get_user(self, cert: ECPCertificate):
        return cert.user
