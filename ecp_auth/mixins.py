from django.contrib.auth import login
from django.contrib.auth.mixins import FormView
from .models import ECPCertificate
from .backends import ECPAuthenticationBackend
from .generator import generate_key_and_certificate, generate_p12
import base64

class ECPGenerateMixin(FormView):

    def form_valid(self, form):
        user = self.request.user
        username = user.username
        taxpayer_id = form.cleaned_data['taxpayer_id']

        # Generate a new key and self-signed certificate for the user
        private_key, cert_pem = generate_key_and_certificate(taxpayer_id, username)

        # Save the certificate in the database
        ECPCertificate.objects.update_or_create(
            user=user,
            defaults={
                'taxpayer_id': taxpayer_id,
                'certificate_pem': cert_pem.decode(),
            }
        )

        # Generate PKCS#12 archive and store it in session for download
        p12_bytes = generate_p12(private_key, cert_pem)
        self.request.session['ecp_p12'] = base64.b64encode(p12_bytes).decode()

        return super().form_valid(form)


class ECPLoginMixin(FormView):

    def form_valid(self, form):
        # cheking password
        user = form.get_user()

        #checking .p12
        signature = form.cleaned_data.get('signature')
        taxpayer_id = form.cleaned_data.get('taxpayer_id')
        nonce_id = form.cleaned_data.get('nonce_id')

        ecp_user = ECPAuthenticationBackend().authenticate(
            request=self.request,
            signature=signature,
            taxpayer_id=taxpayer_id,
            nonce_id=nonce_id
        )

        if ecp_user is not None:
            login(self.request, ecp_user)
            return super().form_valid(form)

        form.add_error(None, "Issue with certificate or signature")
        return self.form_invalid(form)