from django.contrib.auth import login
from django.contrib.auth import authenticate as django_authenticate
from django.http import HttpResponse
from django.views.generic.edit import FormView

from .models import ECPCertificate
from .backends import ECPAuthenticationBackend
from .generator import generate_key_and_certificate, private_key_to_pem


class ECPGenerateMixin(FormView):
    """Mixin for registration views that generates and stores an ECP key pair.

    Add this mixin to a ``CreateView`` to automatically generate an ECDSA key
    pair after a user is created. The private key and certificate are stored in
    the session so they can be served once via ``GET /ecp/keys/``.

    The mixin reads the user from ``form.instance``, so it must be used with a
    ``ModelForm`` whose instance is the newly created user.

    Example::

        class RegisterView(ECPGenerateMixin, CreateView):
            model = User
            form_class = UserCreationForm
            success_url = '/keys/'
    """

    def form_valid(self, response: HttpResponse) -> HttpResponse:
        """Generate a key pair for the new user and store PEM text in session.

        Called automatically after the form is validated and the user is saved.
        Generates an ECDSA P-256 key pair, saves the public certificate to the
        database, and stores both PEM strings in ``request.session``.

        Args:
            response: The form instance with a populated ``.instance`` attribute.

        Returns:
            The HTTP response returned by the parent ``form_valid`` (redirect).
        """
        user = response.instance

        private_key, cert_pem = generate_key_and_certificate(user.username)

        ECPCertificate.objects.update_or_create(
            user=user,
            defaults={'certificate_pem': cert_pem.decode()},
        )

        self.request.session['ecp_key_pem'] = private_key_to_pem(private_key)
        self.request.session['ecp_cert_pem'] = cert_pem.decode()

        return super().form_valid(response)


class ECPLoginMixin(FormView):
    """Mixin for login views that enforces ECP signature verification.

    Add this mixin to a ``FormView``-based login view. It performs two
    sequential authentication checks:

    1. Standard Django password authentication (``authenticate(username, password)``).
    2. ECDSA signature verification via ``ECPAuthenticationBackend``.

    The login form must include the following fields in ``cleaned_data``:

    - ``username`` — the user's username.
    - ``password`` — the user's password.
    - ``signature`` — DER-encoded ECDSA signature of the nonce value (bytes).
    - ``nonce_id`` — primary key of the nonce returned by ``GET /ecp/challenge/``.

    Example::

        class LoginView(ECPLoginMixin, FormView):
            form_class = ECPLoginForm
            success_url = '/dashboard/'
            template_name = 'login.html'
    """

    def form_valid(self, form: object) -> HttpResponse:
        """Authenticate the user via password and ECDSA signature.

        Args:
            form: The validated login form with ``cleaned_data``.

        Returns:
            Redirect to ``success_url`` on success, or re-rendered form with
            an error on failure.
        """
        username: str | None = form.cleaned_data.get('username')
        password: str | None = form.cleaned_data.get('password')
        signature: bytes | None = form.cleaned_data.get('signature')
        nonce_id: int | None = form.cleaned_data.get('nonce_id')

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
