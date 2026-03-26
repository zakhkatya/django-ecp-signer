from django.conf import settings

DEFAULTS = {
    "NONCE_TTL_SECONDS": 300,
}


def get_setting(key: str):
    """Return ECP_AUTH[key] from Django settings, falling back to DEFAULTS."""
    ecp_settings = getattr(settings, "ECP_AUTH", {})
    if key in ecp_settings:
        return ecp_settings[key]
    return DEFAULTS[key]
