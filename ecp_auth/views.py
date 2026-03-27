from django.http import HttpResponse, JsonResponse
from django.views import View

from .models import ECPNonce


class ChallengeView(View):
    """GET /ecp/challenge/ — issue a fresh nonce to the client."""

    def get(self, request):
        nonce = ECPNonce.objects.create()
        return JsonResponse({"nonce": nonce.value, "nonce_id": nonce.pk})


class KeyDisplayView(View):
    """GET /ecp/keys/ — return private key and certificate PEM text from session.

    Called once after registration. The frontend shows the key as backup codes
    for the user to copy and save. Clears the session immediately after serving.
    """

    def get(self, request):
        key_pem = request.session.pop("ecp_key_pem", None)
        cert_pem = request.session.pop("ecp_cert_pem", None)

        if key_pem is None:
            return HttpResponse(status=404)

        return JsonResponse({
            "private_key": key_pem,
            "certificate": cert_pem,
        })
