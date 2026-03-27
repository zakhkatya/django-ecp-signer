import json

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.test import RequestFactory, TestCase

from ecp_auth.models import ECPCertificate, ECPNonce
from ecp_auth.views import CertificateUploadView, ChallengeView, KeyDisplayView, _CHALLENGE_RATE_LIMIT
from tests.conftest import make_cert_and_key

User = get_user_model()

FAKE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n"
FAKE_CERT_PEM = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"


class TestChallengeView(TestCase):

    def setUp(self):
        self.view = ChallengeView.as_view()
        self.factory = RequestFactory()
        cache.clear()

    def test_challenge_returns_nonce_and_id(self):
        response = self.view(self.factory.get("/ecp/challenge/"))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("nonce", data)
        self.assertIn("nonce_id", data)

    def test_challenge_creates_nonce_in_db(self):
        self.view(self.factory.get("/ecp/challenge/"))
        self.assertEqual(ECPNonce.objects.count(), 1)

    def test_rate_limit_returns_429(self):
        for _ in range(_CHALLENGE_RATE_LIMIT):
            self.view(self.factory.get("/ecp/challenge/"))
        response = self.view(self.factory.get("/ecp/challenge/"))
        self.assertEqual(response.status_code, 429)

    def test_rate_limit_uses_x_forwarded_for(self):
        """Requests from distinct X-Forwarded-For IPs have separate rate limits."""
        for _ in range(_CHALLENGE_RATE_LIMIT):
            req = self.factory.get("/ecp/challenge/", HTTP_X_FORWARDED_FOR="1.2.3.4")
            self.view(req)
        req = self.factory.get("/ecp/challenge/", HTTP_X_FORWARDED_FOR="5.6.7.8")
        response = self.view(req)
        self.assertEqual(response.status_code, 200)


class TestKeyDisplayView(TestCase):

    def setUp(self):
        self.view = KeyDisplayView.as_view()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="testuser", password="pw")

    def _request(self, params="", session=None, authenticated=True):
        request = self.factory.get(f"/ecp/keys/{params}")
        request.session = session if session is not None else {}
        request.user = self.user if authenticated else AnonymousUser()
        return request

    def _full_session(self):
        return {"ecp_key_pem": FAKE_KEY_PEM, "ecp_cert_pem": FAKE_CERT_PEM}

    def test_returns_pem_json(self):
        response = self.view(self._request(session=self._full_session()))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["private_key"], FAKE_KEY_PEM)
        self.assertEqual(data["certificate"], FAKE_CERT_PEM)

    def test_json_clears_both_session_keys(self):
        request = self._request(session=self._full_session())
        self.view(request)
        self.assertNotIn("ecp_key_pem", request.session)
        self.assertNotIn("ecp_cert_pem", request.session)

    def test_returns_404_when_no_session(self):
        response = self.view(self._request())
        self.assertEqual(response.status_code, 404)

    def test_unauthenticated_returns_403(self):
        response = self.view(self._request(session=self._full_session(), authenticated=False))
        self.assertEqual(response.status_code, 403)

    def test_download_private_key_file(self):
        request = self._request(params="?file=private_key", session=self._full_session())
        response = self.view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-pem-file")
        self.assertIn("private_key.pem", response["Content-Disposition"])
        self.assertEqual(response.content.decode(), FAKE_KEY_PEM)

    def test_download_private_key_clears_only_key_from_session(self):
        session = self._full_session()
        request = self._request(params="?file=private_key", session=session)
        self.view(request)
        self.assertNotIn("ecp_key_pem", request.session)
        self.assertIn("ecp_cert_pem", request.session)

    def test_download_certificate_file(self):
        request = self._request(params="?file=certificate", session=self._full_session())
        response = self.view(request)
        self.assertEqual(response.status_code, 200)
        self.assertIn("certificate.pem", response["Content-Disposition"])
        self.assertEqual(response.content.decode(), FAKE_CERT_PEM)

    def test_download_certificate_clears_only_cert_from_session(self):
        session = self._full_session()
        request = self._request(params="?file=certificate", session=session)
        self.view(request)
        self.assertIn("ecp_key_pem", request.session)
        self.assertNotIn("ecp_cert_pem", request.session)

    def test_unknown_file_param_returns_400(self):
        request = self._request(params="?file=unknown", session=self._full_session())
        response = self.view(request)
        self.assertEqual(response.status_code, 400)


class TestCertificateUploadView(TestCase):

    def setUp(self):
        self.view = CertificateUploadView.as_view()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="testuser", password="pw")

    def _post(self, file_content=None, filename="certificate.pem", authenticated=True):
        if file_content is not None:
            from django.core.files.uploadedfile import SimpleUploadedFile
            f = SimpleUploadedFile(filename, file_content, content_type="application/x-pem-file")
            request = self.factory.post("/ecp/certificate/", {"certificate": f})
        else:
            request = self.factory.post("/ecp/certificate/")
        request.user = self.user if authenticated else AnonymousUser()
        return self.view(request)

    def test_upload_valid_cert_stores_in_db(self):
        _, cert_pem = make_cert_and_key(common_name="testuser")
        response = self._post(cert_pem)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(ECPCertificate.objects.filter(user=self.user).exists())

    def test_upload_replaces_existing_cert(self):
        _, cert_pem1 = make_cert_and_key(common_name="testuser")
        _, cert_pem2 = make_cert_and_key(common_name="testuser")
        self._post(cert_pem1)
        self._post(cert_pem2)
        self.assertEqual(ECPCertificate.objects.filter(user=self.user).count(), 1)
        self.assertEqual(ECPCertificate.objects.get(user=self.user).certificate_pem, cert_pem2.decode())

    def test_no_file_returns_400(self):
        response = self._post(file_content=None)
        self.assertEqual(response.status_code, 400)

    def test_invalid_pem_returns_400(self):
        response = self._post(b"not a certificate")
        self.assertEqual(response.status_code, 400)

    def test_expired_cert_returns_400(self):
        _, cert_pem = make_cert_and_key(common_name="testuser", expired=True)
        response = self._post(cert_pem)
        self.assertEqual(response.status_code, 400)

    def test_wrong_cn_returns_400(self):
        _, cert_pem = make_cert_and_key(common_name="otheruser")
        response = self._post(cert_pem)
        self.assertEqual(response.status_code, 400)

    def test_unauthenticated_returns_403(self):
        _, cert_pem = make_cert_and_key(common_name="testuser")
        response = self._post(cert_pem, authenticated=False)
        self.assertEqual(response.status_code, 403)
