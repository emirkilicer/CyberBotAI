from django.conf import settings
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError

from core.services import enrollment


class Command(BaseCommand):
    help = "Issue a one-time 2FA enrollment token for an existing account."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument(
            "--ttl",
            type=int,
            default=enrollment.DEFAULT_TTL_SECONDS,
            help="Token lifetime in seconds (default: 900).",
        )

    def handle(self, *args, **options):
        username = options["username"]
        user = User.objects.filter(username=username, is_active=True).first()
        if user is None:
            raise CommandError(f"Active user not found: {username}")

        token = enrollment.issue_token(user, ttl_seconds=options["ttl"])
        base = getattr(settings, "SITE_URL", "http://localhost:8081").rstrip("/")
        self.stdout.write(self.style.SUCCESS("Enrollment token issued (single use)."))
        self.stdout.write(f"{base}/setup-2fa/?token={token}")
        self.stdout.write(
            "The token expires in "
            f"{options['ttl']} seconds and is stored only as a hash."
        )
