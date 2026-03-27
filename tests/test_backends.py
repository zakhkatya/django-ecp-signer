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
    """Creates a valid ECPCertificate in the DB, returns private_key."""
    key, cert_pem = make_cert_and_key(common_name=user.username)
    ECPCertificate.objects.create(user=user, certificate_pem=cert_pem.decode())
    return key


@pytest.mark.django_db
class TestECPAuthenticationBackend:

    def test_successful_authentication(self, user, nonce, registered_cert):
        signature = sign_nonce(registered_cert, nonce.value)
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=signature,
            username=user.username,
            nonce_id=nonce.pk,
        )
        assert result == user

    def test_nonce_consumed_after_auth(self, user, nonce, registered_cert):
        signature = sign_nonce(registered_cert, nonce.value)
        ECPAuthenticationBackend().authenticate(
            request=None,
            signature=sign_nonce(registered_cert, nonce.value),
            username=user.username,
            nonce_id=nonce.pk,
        )
        nonce.refresh_from_db()
        assert nonce.used is True

    def test_missing_signature_returns_none(self, nonce, user):
        result = ECPAuthenticationBackend().authenticate(
            request=None, signature=None, username=user.username, nonce_id=nonce.pk
        )
        assert result is None

    def test_missing_username_returns_none(self, nonce):
        result = ECPAuthenticationBackend().authenticate(
            request=None, signature=b"sig", username=None, nonce_id=nonce.pk
        )
        assert result is None

    def test_missing_nonce_id_returns_none(self, user):
        result = ECPAuthenticationBackend().authenticate(
            request=None, signature=b"sig", username=user.username, nonce_id=None
        )
        assert result is None

    def test_nonce_not_found_returns_none(self, db, user):
        result = ECPAuthenticationBackend().authenticate(
            request=None, signature=b"sig", username=user.username, nonce_id=99999
        )
        assert result is None

    def test_expired_nonce_returns_none(self, user, registered_cert, db):
        nonce = ECPNonce.objects.create()
        ECPNonce.objects.filter(pk=nonce.pk).update(
            created_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        )
        nonce.refresh_from_db()
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=sign_nonce(registered_cert, nonce.value),
            username=user.username,
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_used_nonce_returns_none(self, user, nonce, registered_cert):
        nonce.consume()
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=sign_nonce(registered_cert, nonce.value),
            username=user.username,
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_user_not_found_returns_none(self, nonce, db):
        result = ECPAuthenticationBackend().authenticate(
            request=None, signature=b"sig", username="nobody", nonce_id=nonce.pk
        )
        assert result is None

    def test_certificate_not_found_returns_none(self, user, nonce):
        result = ECPAuthenticationBackend().authenticate(
            request=None, signature=b"sig", username=user.username, nonce_id=nonce.pk
        )
        assert result is None

    def test_expired_certificate_returns_none(self, user, nonce, db):
        key, cert_pem = make_cert_and_key(expired=True)
        ECPCertificate.objects.create(user=user, certificate_pem=cert_pem.decode())
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=sign_nonce(key, nonce.value),
            username=user.username,
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_invalid_signature_bytes_returns_none(self, user, nonce, registered_cert):
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=b"not_a_valid_signature",
            username=user.username,
            nonce_id=nonce.pk,
        )
        assert result is None

    def test_wrong_key_returns_none(self, user, nonce, registered_cert):
        wrong_key, _ = make_cert_and_key(common_name="other")
        result = ECPAuthenticationBackend().authenticate(
            request=None,
            signature=sign_nonce(wrong_key, nonce.value),
            username=user.username,
            nonce_id=nonce.pk,
        )
        assert result is None
