from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views import View

from .models import ECPNonce

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


class KeyDisplayView(View):
    """Serve the generated private key and certificate PEM text from session.

    ``GET /ecp/keys/`` — returns the private key and certificate PEM strings
    stored in the session by ``ECPGenerateMixin``. The session data is cleared
    immediately after serving, making this a one-time endpoint.

    Requires the user to be authenticated (returns 403 otherwise).
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        """Return PEM text from session and clear it.

        Args:
            request: The incoming HTTP request. Must have ``ecp_key_pem`` and
                ``ecp_cert_pem`` values in the session.

        Returns:
            ``200 OK`` with ``{"private_key": str, "certificate": str}``,
            ``403 Forbidden`` if the user is not authenticated, or
            ``404 Not Found`` if the session data is absent.

        """
        if not request.user.is_authenticated:
            return HttpResponse(status=403)

        key_pem = request.session.pop("ecp_key_pem", None)
        cert_pem = request.session.pop("ecp_cert_pem", None)

        if key_pem is None or cert_pem is None:
            return HttpResponse(status=404)

        return JsonResponse(
            {
                "private_key": key_pem,
                "certificate": cert_pem,
            }
        )
