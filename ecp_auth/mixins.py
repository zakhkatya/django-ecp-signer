from django.contrib.auth import login
from django.contrib.auth import authenticate as django_authenticate
from django.views.generic.edit import FormView

from .models import ECPCertificate
from .backends import ECPAuthenticationBackend
from .generator import generate_key_and_certificate, private_key_to_pem


class ECPGenerateMixin(FormView):

    def form_valid(self, form):
        user = form.instance

        private_key, cert_pem = generate_key_and_certificate(user.username)

        ECPCertificate.objects.update_or_create(
            user=user,
            defaults={'certificate_pem': cert_pem.decode()},
        )

        self.request.session['ecp_key_pem'] = private_key_to_pem(private_key)
        self.request.session['ecp_cert_pem'] = cert_pem.decode()

        return super().form_valid(form)


class ECPLoginMixin(FormView):

    def form_valid(self, form):
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')
        signature = form.cleaned_data.get('signature')
        nonce_id = form.cleaned_data.get('nonce_id')

        # Step 1: standard password check
        user = django_authenticate(request=self.request, username=username, password=password)
        if user is None:
            form.add_error(None, "Invalid username or password")
            return self.form_invalid(form)

        # Step 2: ECP signature check
        ecp_user = ECPAuthenticationBackend().authenticate(
            request=self.request,
            signature=signature,
            username=username,
            nonce_id=nonce_id,
        )
        if ecp_user is None or ecp_user != user:
            form.add_error(None, "Issue with certificate or signature")
            return self.form_invalid(form)

        login(self.request, user, backend='django.contrib.auth.backends.ModelBackend')
        return super().form_valid(form)
