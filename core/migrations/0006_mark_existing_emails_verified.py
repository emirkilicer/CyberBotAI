import hashlib

from django.db import migrations
from django.utils import timezone


def mark_existing_users_verified(apps, schema_editor):
    """Do not lock out accounts that predate email verification."""
    User = apps.get_model("auth", "User")
    EmailVerification = apps.get_model("core", "EmailVerification")
    now = timezone.now()
    for user in User.objects.filter(is_active=True).iterator():
        token_hash = hashlib.sha256(f"legacy-email-verified:{user.pk}".encode()).hexdigest()
        EmailVerification.objects.get_or_create(
            user=user,
            defaults={
                "token_hash": token_hash,
                "expires_at": now,
                "verified_at": now,
            },
        )


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0005_emailverification"),
    ]

    operations = [
        migrations.RunPython(mark_existing_users_verified, migrations.RunPython.noop),
    ]
