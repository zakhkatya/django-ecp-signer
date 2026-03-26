from datetime import timedelta


def get_nonce_lifetime() -> timedelta:
    """Return NONCE_LIFETIME from Django settings, read lazily to avoid
    import-time access before settings are configured."""
    from django.conf import settings
    return getattr(settings, "NONCE_LIFETIME", timedelta(minutes=5))
