from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone
import secrets

from . import conf


def gen_secret_token():
    return secrets.token_hex(32)


class ECPNonce(models.Model):
    """This model represents ecp nonce."""

    value = models.CharField(max_length=64, default=gen_secret_token, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)

    def is_valid(self):
        nonce_age = timezone.now() - self.created_at

        return (not self.used) and (
            nonce_age.total_seconds() < conf.get_nonce_lifetime().total_seconds()
        )

    def consume(self):
        self.used = True
        self.save()


class ECPCertificate(models.Model):
    """This model represents ecp certificate."""

    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE)
    taxpayer_id = models.CharField(max_length=10, unique=True)
    certificate_pem = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
