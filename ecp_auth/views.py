import base64

from django.http import HttpResponse, JsonResponse
from django.views import View

from .models import ECPNonce


class ChallengeView(View):
    """GET /ecp/challenge/ — issue a fresh nonce to the client."""

    def get(self, request):
        nonce = ECPNonce.objects.create()
        return JsonResponse({"nonce": nonce.value, "nonce_id": nonce.pk})


class CertificateDownloadView(View):
    """GET /ecp/certificate/download/ — return the PKCS#12 archive from session."""

    def get(self, request):
        p12_b64 = request.session.pop("ecp_p12", None)
        if p12_b64 is None:
            return HttpResponse(status=404)

        p12_bytes = base64.b64decode(p12_b64)
        return HttpResponse(
            content=p12_bytes,
            content_type="application/x-pkcs12",
            headers={"Content-Disposition": 'attachment; filename="user.p12"'},
        )
