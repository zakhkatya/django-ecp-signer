from django.conf import settings
from datetime import timedelta


NONCE_LIFETIME = getattr(settings, "NONCE_LIFETIME", timedelta(minutes=5))
