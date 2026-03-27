from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views import View

from .certificate import CertificateParser
from .exceptions import InvalidCertificateError
from .models import ECPCertificate, ECPNonce

_CHALLENGE_RATE_LIMIT = 10  # max requests per window
_CHALLENGE_RATE_WINDOW = 60  # window size in seconds


def _get_client_ip(request: HttpRequest) -> str:
    """Return the real client IP, respecting ``X-Forwarded-For`` if present.

    Args:
        request: The incoming HTTP request.

    Returns:
        The client IP string, or ``"unknown"`` if it cannot be determined.

    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


class ChallengeView(View):
    """Issue a one-time nonce to the client.

    ``GET /ecp/challenge/`` — creates a fresh ``ECPNonce`` and returns its value
    and primary key as JSON. Rate-limited to ``_CHALLENGE_RATE_LIMIT`` requests
    per ``_CHALLENGE_RATE_WINDOW`` seconds per IP address.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        """Create a nonce and return it as JSON.

        Args:
            request: The incoming HTTP request.

        Returns:
            ``200 OK`` with ``{"nonce": str, "nonce_id": int}``, or
            ``429 Too Many Requests`` if the rate limit is exceeded.

        """
        ip = _get_client_ip(request)
        key = f"ecp_challenge:{ip}"

        if not cache.add(key, 1, timeout=_CHALLENGE_RATE_WINDOW) and cache.incr(key) > _CHALLENGE_RATE_LIMIT:
            return HttpResponse(status=429)

        nonce = ECPNonce.objects.create()
        return JsonResponse({"nonce": nonce.value, "nonce_id": nonce.pk})


_FILE_PRIVATE_KEY = "private_key"
_FILE_CERTIFICATE = "certificate"


class KeyDisplayView(View):
    """Serve the generated private key and certificate PEM text from session.

    ``GET /ecp/keys/`` — returns PEM strings stored in the session by
    ``ECPGenerateMixin``. The session data is cleared immediately after serving,
    making this a one-time endpoint.

    Supported ``?file=`` query values:

    - ``private_key`` — download ``private_key.pem`` (encrypted, PKCS#8)
    - ``certificate`` — download ``certificate.pem`` (public, safe to share)
    - omitted — return JSON with both fields

    Requires the user to be authenticated (returns 403 otherwise).
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        """Return PEM data from session as JSON or individual downloadable files.

        Args:
            request: The incoming HTTP request. Must have ``ecp_key_pem`` and
                ``ecp_cert_pem`` values in the session.

        Returns:
            ``200 OK`` with JSON or a PEM file depending on the ``file``
            query parameter, ``400 Bad Request`` for an unknown ``file`` value,
            ``403 Forbidden`` if the user is not authenticated, or
            ``404 Not Found`` if the session data is absent.

        """
        if not request.user.is_authenticated:
            return HttpResponse(status=403)

        file_param = request.GET.get("file")
        if file_param is not None and file_param not in (_FILE_PRIVATE_KEY, _FILE_CERTIFICATE):
            return JsonResponse(
                {"error": f"Unknown file type. Use '{_FILE_PRIVATE_KEY}' or '{_FILE_CERTIFICATE}'."},
                status=400,
            )

        key_pem = request.session.get("ecp_key_pem")
        cert_pem = request.session.get("ecp_cert_pem")

        if key_pem is None or cert_pem is None:
            return HttpResponse(status=404)

        if file_param == _FILE_PRIVATE_KEY:
            request.session.pop("ecp_key_pem", None)
            return _pem_file_response(key_pem, "private_key.pem")

        if file_param == _FILE_CERTIFICATE:
            request.session.pop("ecp_cert_pem", None)
            return _pem_file_response(cert_pem, "certificate.pem")

        # No file param — return JSON and clear both
        request.session.pop("ecp_key_pem", None)
        request.session.pop("ecp_cert_pem", None)
        return JsonResponse({"private_key": key_pem, "certificate": cert_pem})


class CertificateUploadView(View):
    """Accept a PEM certificate file uploaded by an authenticated user.

    ``POST /ecp/certificate/`` — stores the uploaded certificate as the user's
    active signing credential, replacing any previously generated one. Useful
    when a user wants to bring their own key pair (BYOK) or re-register a
    certificate downloaded earlier via ``GET /ecp/keys/?format=file``.

    The request must be ``multipart/form-data`` with a ``certificate`` field
    containing the PEM file (the ``certificate.pem`` from the downloaded ZIP).
    The private key is never sent to or stored by the server.

    Requires the user to be authenticated (returns 403 otherwise).
    """

    def post(self, request: HttpRequest) -> HttpResponse:
        """Validate and store the uploaded certificate.

        Args:
            request: A ``multipart/form-data`` POST request with a
                ``certificate`` file field.

        Returns:
            ``200 OK`` with ``{"status": "ok"}`` on success,
            ``400 Bad Request`` with ``{"error": str}`` if the certificate is
            missing, invalid, expired, or its CN does not match the username,
            ``403 Forbidden`` if the user is not authenticated.

        """
        if not request.user.is_authenticated:
            return HttpResponse(status=403)

        cert_file = request.FILES.get("certificate")
        if cert_file is None:
            return JsonResponse({"error": "No certificate file provided"}, status=400)

        cert_bytes = cert_file.read()

        try:
            parser = CertificateParser(cert_bytes)
        except InvalidCertificateError as exc:
            return JsonResponse({"error": str(exc)}, status=400)

        if parser.is_expired():
            return JsonResponse({"error": "Certificate is expired or not yet valid"}, status=400)

        if parser.get_common_name() != request.user.username:
            return JsonResponse({"error": "Certificate CN does not match your username"}, status=400)

        ECPCertificate.objects.update_or_create(
            user=request.user,
            defaults={"certificate_pem": cert_bytes.decode()},
        )
        return JsonResponse({"status": "ok"})


def _pem_file_response(pem: str, filename: str) -> HttpResponse:
    """Build an HTTP response that downloads a PEM file.

    Args:
        pem: PEM-encoded string content.
        filename: The suggested download filename (e.g. ``private_key.pem``).

    Returns:
        An ``HttpResponse`` with ``Content-Disposition: attachment`` and
        ``Content-Type: application/x-pem-file``.

    """
    response = HttpResponse(pem, content_type="application/x-pem-file")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
