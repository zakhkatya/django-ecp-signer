import json

from django.test import RequestFactory, TestCase

from ecp_auth.models import ECPNonce
from ecp_auth.views import ChallengeView, KeyDisplayView

FAKE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n"
FAKE_CERT_PEM = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"


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


class TestKeyDisplayView(TestCase):

    def setUp(self):
        self.view = KeyDisplayView.as_view()
        self.factory = RequestFactory()

    def _request(self, session=None):
        request = self.factory.get("/ecp/keys/")
        request.session = session if session is not None else {}
        return request

    def test_returns_pem_json(self):
        session = {"ecp_key_pem": FAKE_KEY_PEM, "ecp_cert_pem": FAKE_CERT_PEM}
        response = self.view(self._request(session))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data["private_key"], FAKE_KEY_PEM)
        self.assertEqual(data["certificate"], FAKE_CERT_PEM)

    def test_clears_session_after_serving(self):
        session = {"ecp_key_pem": FAKE_KEY_PEM, "ecp_cert_pem": FAKE_CERT_PEM}
        request = self._request(session)
        self.view(request)
        self.assertNotIn("ecp_key_pem", request.session)
        self.assertNotIn("ecp_cert_pem", request.session)

    def test_returns_404_when_no_session(self):
        response = self.view(self._request())
        self.assertEqual(response.status_code, 404)
