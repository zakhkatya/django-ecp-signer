from django.contrib.auth.backends import ModelBackend
from django.utils import timezone
from .models import ECPCertificate, Nonce
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.exceptions import InvalidSignature
import base64


class ECPAuthenticationBackend(ModelBackend):

    def authenticate(self, request, signature=None, taxpayer_id=None, nonce_id=None, **kwargs):
        # Get nonce
        try:
            nonce = Nonce.objects.get(id=nonce_id, consumed=False)
        except Nonce.DoesNotExist:
            return None

        # Get certificate from DB
        try:
            cert_entry = ECPCertificate.objects.get(taxpayer_id=taxpayer_id)
        except ECPCertificate.DoesNotExist:
            return None

        cert_pem = cert_entry.certificate_pem.encode()

        # Verify signature
        if not self._verify_signature(nonce.value.encode(), signature, cert_pem):
            return None

        # Check expiration
        if not self._check_expired(cert_pem):
            return None

        # Mark nonce as consumed
        nonce.consume()
        return cert_entry.user

    def _verify_signature(self, nonce_bytes, signature_b64, cert_pem):
        try:
            signature = base64.b64decode(signature_b64)
            cert = x509.load_pem_x509_certificate(cert_pem)
            public_key = cert.public_key()
            public_key.verify(signature, nonce_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False

    def _check_expired(self, cert_pem):
        cert = x509.load_pem_x509_certificate(cert_pem)
        now = timezone.now()
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        return not_before <= now <= not_after