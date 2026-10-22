from django.db import migrations

from core.crypto import decrypt_secret, encrypt_secret, is_encrypted


def encrypt_existing_secrets(apps, schema_editor):
    """Encrypt TOTP secrets that were stored in plaintext before this release."""
    UserTwoFactor = apps.get_model("core", "UserTwoFactor")
    for row in UserTwoFactor.objects.exclude(otp_secret__isnull=True).exclude(otp_secret=""):
        if not is_encrypted(row.otp_secret):
            row.otp_secret = encrypt_secret(row.otp_secret)
            row.save(update_fields=["otp_secret"])


def decrypt_existing_secrets(apps, schema_editor):
    """Best-effort rollback to the previous plaintext format."""
    UserTwoFactor = apps.get_model("core", "UserTwoFactor")
    for row in UserTwoFactor.objects.exclude(otp_secret__isnull=True).exclude(otp_secret=""):
        if is_encrypted(row.otp_secret):
            row.otp_secret = decrypt_secret(row.otp_secret, allow_legacy=False)
            row.save(update_fields=["otp_secret"])


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0002_alter_usertwofactor_options_and_more"),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_secrets, decrypt_existing_secrets),
    ]
