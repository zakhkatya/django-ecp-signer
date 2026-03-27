import pytest
from unittest.mock import MagicMock, patch
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from django.contrib.auth import get_user_model
from django.test import RequestFactory

from ecp_auth.mixins import ECPGenerateMixin, ECPLoginMixin
from ecp_auth.models import ECPCertificate, ECPNonce
from tests.conftest import make_cert_and_key

User = get_user_model()


# --- Concrete views for testing ---

class ConcreteGenerateView(ECPGenerateMixin):
    success_url = "/success/"


class ConcreteLoginView(ECPLoginMixin):
    success_url = "/dashboard/"

    def form_invalid(self, form):
        from django.http import HttpResponse
        return HttpResponse(status=400)


def _make_request(session=None):
    request = RequestFactory().get("/")
    request.session = session if session is not None else {}
    return request


def _make_form(instance=None, cleaned_data=None):
    form = MagicMock()
    form.instance = instance
    form.cleaned_data = cleaned_data or {}
    return form


# --- ECPGenerateMixin ---

@pytest.mark.django_db
class TestECPGenerateMixin:

    def _run(self, user):
        view = ConcreteGenerateView()
        view.request = _make_request()
        view.kwargs = {}
        view.args = ()
        view.form_valid(_make_form(instance=user))
        return view

    def test_creates_certificate_in_db(self):
        user = User.objects.create_user(username="genuser", password="pass")
        self._run(user)
        assert ECPCertificate.objects.filter(user=user).exists()

    def test_certificate_pem_stored(self):
        user = User.objects.create_user(username="genuser2", password="pass")
        self._run(user)
        cert = ECPCertificate.objects.get(user=user)
        assert "BEGIN CERTIFICATE" in cert.certificate_pem

    def test_key_pem_in_session(self):
        user = User.objects.create_user(username="genuser3", password="pass")
        view = self._run(user)
        assert "ecp_key_pem" in view.request.session
        assert view.request.session["ecp_key_pem"].startswith("-----BEGIN PRIVATE KEY-----")

    def test_cert_pem_in_session(self):
        user = User.objects.create_user(username="genuser4", password="pass")
        view = self._run(user)
        assert "ecp_cert_pem" in view.request.session
        assert view.request.session["ecp_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")

    def test_update_or_create_replaces_old_cert(self):
        user = User.objects.create_user(username="genuser5", password="pass")
        self._run(user)
        self._run(user)  # second call should replace, not duplicate
        assert ECPCertificate.objects.filter(user=user).count() == 1


# --- ECPLoginMixin ---

@pytest.mark.django_db
class TestECPLoginMixin:

    def _make_login_view(self, cleaned_data):
        view = ConcreteLoginView()
        view.request = _make_request()
        view.kwargs = {}
        view.args = ()
        view.object = None
        return view, _make_form(cleaned_data=cleaned_data)

    def test_successful_login(self):
        user = User.objects.create_user(username="loginuser", password="correct")
        key, cert_pem = make_cert_and_key(common_name="loginuser")
        ECPCertificate.objects.create(user=user, certificate_pem=cert_pem.decode())
        nonce = ECPNonce.objects.create()
        signature = key.sign(nonce.value.encode(), ec.ECDSA(hashes.SHA256()))

        view, form = self._make_login_view({
            "username": "loginuser",
            "password": "correct",
            "signature": signature,
            "nonce_id": nonce.pk,
        })

        with patch("ecp_auth.mixins.login") as mock_login:
            view.form_valid(form)
            mock_login.assert_called_once()
            called_user = mock_login.call_args[0][1]
            assert called_user == user

    def test_wrong_password_rejected(self):
        user = User.objects.create_user(username="loginuser2", password="correct")
        key, cert_pem = make_cert_and_key(common_name="loginuser2")
        ECPCertificate.objects.create(user=user, certificate_pem=cert_pem.decode())
        nonce = ECPNonce.objects.create()
        signature = key.sign(nonce.value.encode(), ec.ECDSA(hashes.SHA256()))

        view, form = self._make_login_view({
            "username": "loginuser2",
            "password": "WRONG",
            "signature": signature,
            "nonce_id": nonce.pk,
        })

        with patch("ecp_auth.mixins.login") as mock_login:
            view.form_valid(form)
            mock_login.assert_not_called()

    def test_wrong_signature_rejected(self):
        user = User.objects.create_user(username="loginuser3", password="correct")
        key, cert_pem = make_cert_and_key(common_name="loginuser3")
        ECPCertificate.objects.create(user=user, certificate_pem=cert_pem.decode())
        nonce = ECPNonce.objects.create()

        view, form = self._make_login_view({
            "username": "loginuser3",
            "password": "correct",
            "signature": b"badsignature",
            "nonce_id": nonce.pk,
        })

        with patch("ecp_auth.mixins.login") as mock_login:
            view.form_valid(form)
            mock_login.assert_not_called()
