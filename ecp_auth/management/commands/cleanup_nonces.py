from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from ecp_auth import conf
from ecp_auth.models import ECPNonce


class Command(BaseCommand):
    """Management command to delete stale ECP nonces from the database.

    Run periodically (e.g. via cron or Celery beat) to prevent table bloat::

        python manage.py cleanup_nonces
    """

    help = "Delete used and expired ECP nonces from the database."

    def handle(self, *args: object, **options: object) -> None:
        """Delete all used and expired nonces.

        Args:
            *args: Unused positional arguments.
            **options: Unused keyword arguments.

        """
        cutoff = timezone.now() - conf.get_nonce_lifetime()
        deleted, _ = ECPNonce.objects.filter(Q(used=True) | Q(created_at__lt=cutoff)).delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted} stale nonce(s)."))
