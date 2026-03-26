from django.views import View
from django.http import JsonResponse, HttpResponse
from .models import Nonce
import base64
import os


class ChallengeView(View):

    def get(self, request, *args, **kwargs):
        # nonce 
        nonce_obj = Nonce.objects.create(value=os.urandom(16).hex())
        data = {
            "nonce": nonce_obj.value,
            "nonce_id": nonce_obj.id
        }
        return JsonResponse(data)


class CertificateDownloadView(View):

    def get(self, request, *args, **kwargs):
        p12_b64 = request.session.pop('ecp_p12', None)
        if not p12_b64:
            return HttpResponse("PKCS#12 file not found in session", status=404)

        p12_bytes = base64.b64decode(p12_b64)

        response = HttpResponse(
            p12_bytes,
            content_type='application/x-pkcs12',
        )
        response['Content-Disposition'] = 'attachment; filename="user.p12"'
        return response