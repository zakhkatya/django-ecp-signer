import datetime

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from django.contrib.auth import get_user_model

from ecp_auth.backends import ECPAuthenticationBackend
from ecp_auth.models import ECPCertificate, ECPNonce
from tests.conftest import make_cert_and_key

User = get_user_model()


def sign_nonce(private_key, nonce_value: str) -> bytes:
    return private_key.sign(nonce_value.encode(), ec.ECDSA(hashes.SHA256()))


@pytest.fixture
def user(db):
    return User.objects.create_user(username="testuser", password="testpassword")


@pytest.fixture
def nonce(db):
    return ECPNonce.objects.create()


@pytest.fixture
def registered_cert(db, user):
    """Creates a valid ECPCertificate in the DB, returns (private_key, taxpayer_id)."""
    key, cert_pem = make_cert_and_key(taxpayer_id="1234567890")
    ECPCertificate.objects.create(
        user=user,
        taxpayer_id="1234567890",
        certificate_pem=cert_pem.decode(),
    )
    return key, "1234567890"


@pytest.mark.django_db
class TestECPAuthenticationBackend:

    def test_successful_authentication(self, user, nonce, registered_cert):
        key, taxpayer_id = registered_cert
        signature = sign_nonce(key, nonce.value)
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=signature,
            taxpayer_id=taxpayer_id,
            nonce_id=nonce.pk,
        )
        assert result == user

    def test_nonce_consumed_after_auth(self, user, nonce, registered_cert):
        key, taxpayer_id = registered_cert
        signature = sign_nonce(key, nonce.value)
        ECPAuthenticationBackend().authenticate(
            request=None,
            signature=signature,
            taxpayer_id=taxpayer_id,
            nonce_id=nonce.pk,
        )
        nonce.refresh_from_db()
        assert nonce.used is True

    def test_missing_signature_returns_none(self, nonce):
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=None,
            taxpayer_id="1234567890",
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_missing_taxpayer_id_returns_none(self, nonce):
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=b"sig",
            taxpayer_id=None,
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_missing_nonce_id_returns_none(self, db):
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=b"sig",
            taxpayer_id="1234567890",
            nonce_id=None,
        )
        assert result is None

    def test_nonce_not_found_returns_none(self, db):
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=b"sig",
            taxpayer_id="1234567890",
            nonce_id=99999,
        )
        assert result is None

    def test_expired_nonce_returns_none(self, user, registered_cert, db):
        key, taxpayer_id = registered_cert
        nonce = ECPNonce.objects.create()
        ECPNonce.objects.filter(pk=nonce.pk).update(
            created_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        )
        nonce.refresh_from_db()
        signature = sign_nonce(key, nonce.value)
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=signature,
            taxpayer_id=taxpayer_id,
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_used_nonce_returns_none(self, user, nonce, registered_cert):
        key, taxpayer_id = registered_cert
        nonce.consume()
        signature = sign_nonce(key, nonce.value)
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=signature,
            taxpayer_id=taxpayer_id,
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_certificate_not_found_returns_none(self, nonce, db):
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=b"sig",
            taxpayer_id="0000000000",
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_expired_certificate_returns_none(self, user, nonce, db):
        key, cert_pem = make_cert_and_key(expired=True)
        ECPCertificate.objects.create(
            user=user,
            taxpayer_id="1234567890",
            certificate_pem=cert_pem.decode(),
        )
        signature = sign_nonce(key, nonce.value)
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=signature,
            taxpayer_id="1234567890",
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_invalid_signature_bytes_returns_none(self, user, nonce, registered_cert):
        _, taxpayer_id = registered_cert
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=b"not_a_valid_signature",
            taxpayer_id=taxpayer_id,
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_wrong_key_returns_none(self, user, nonce, registered_cert):
        _, taxpayer_id = registered_cert
        wrong_key, _ = make_cert_and_key(taxpayer_id="9999999999")
        signature = sign_nonce(wrong_key, nonce.value)
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=signature,
            taxpayer_id=taxpayer_id,
            nonce_id=nonce.pk,
        )
        assert result is None
