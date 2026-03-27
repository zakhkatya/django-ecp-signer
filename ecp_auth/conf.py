from datetime import timedelta


def get_nonce_lifetime() -> timedelta:
    """Return the configured nonce lifetime from Django settings.

    Reads ``NONCE_LIFETIME`` from ``django.conf.settings`` lazily (at call
    time rather than import time) so that Django settings are guaranteed to be
    configured before this function is invoked.

    Returns:
        The nonce lifetime as a ``timedelta``. Defaults to 5 minutes if
        ``NONCE_LIFETIME`` is not set.

    Raises:
        django.core.exceptions.ImproperlyConfigured: If ``NONCE_LIFETIME`` is
            set to a value that is not a ``datetime.timedelta``.

    """
    from django.conf import settings
    from django.core.exceptions import ImproperlyConfigured

    value = getattr(settings, "NONCE_LIFETIME", timedelta(minutes=5))
    if not isinstance(value, timedelta):
        raise ImproperlyConfigured(f"NONCE_LIFETIME must be a datetime.timedelta, got {type(value).__name__}")
    return value
