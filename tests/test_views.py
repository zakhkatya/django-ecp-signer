import base64
import json

from django.test import RequestFactory, TestCase

from ecp_auth.models import ECPNonce
from ecp_auth.views import CertificateDownloadView, ChallengeView


class TestChallengeView(TestCase):

    def setUp(self):
        self.view = ChallengeView.as_view()
        self.factory = RequestFactory()

    def test_challenge_returns_nonce_and_id(self):
        response = self.view(self.factory.get("/ecp/challenge/"))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("nonce", data)
        self.assertIn("nonce_id", data)

    def test_challenge_creates_nonce_in_db(self):
        self.view(self.factory.get("/ecp/challenge/"))
        self.assertEqual(ECPNonce.objects.count(), 1)


class TestCertificateDownloadView(TestCase):

    def setUp(self):
        self.view = CertificateDownloadView.as_view()
        self.factory = RequestFactory()

    def _request(self, session=None):
        request = self.factory.get("/ecp/certificate/download/")
        request.session = session if session is not None else {}
        return request

    def test_download_returns_p12_file(self):
        p12_bytes = b"fake-p12-content"
        request = self._request({"ecp_p12": base64.b64encode(p12_bytes).decode()})
        response = self.view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-pkcs12")
        self.assertIn("user.p12", response["Content-Disposition"])
        self.assertEqual(response.content, p12_bytes)

    def test_download_clears_session(self):
        session = {"ecp_p12": base64.b64encode(b"fake").decode()}
        request = self._request(session)
        self.view(request)
        self.assertNotIn("ecp_p12", request.session)

    def test_download_without_session_404(self):
        response = self.view(self._request())
        self.assertEqual(response.status_code, 404)
