from django.contrib.auth import login
from django.contrib.auth.mixins import FormView
from .models import ECPCertificate
from .backends import ECPAuthenticationBackend

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import NameOID
from cryptography import x509
import datetime

class ECPGenerateMixin(FormView):

    def form_valid(self, form):
        user = self.request.user
        username = user.username
        taxpayer_id = form.cleaned_data['taxpayer_id']

        private_key = ec.generate_private_key(ec.SECP256R1())

        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # certificate in db
        ECPCertificate.objects.create(
            user=user,
            cert_pem=cert_pem,
            taxpayer_id=taxpayer_id
        )

        # generate .p12
        p12 = pkcs12.serialize_key_and_certificates(
            name=username.encode(),
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(b"change_me")
        )

        self.request.session['ecp_p12'] = p12

        # return .p12 to user without saving it in db
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