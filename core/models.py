from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

from .crypto import decrypt_secret, encrypt_secret


class UserTwoFactor(models.Model):
    """Second factor state for a user.

    The TOTP secret is stored encrypted (see ``core.crypto``); use
    ``set_otp_secret`` / ``get_otp_secret`` instead of touching the column.
    """

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="two_factor")

    otp_secret = models.CharField(max_length=255, blank=True, null=True)

    is_enabled = models.BooleanField(default=False)

    # Last accepted TOTP time step, used to reject code replay.
    last_used_step = models.BigIntegerField(blank=True, null=True)

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Two-factor authentication"
        verbose_name_plural = "Two-factor authentication"

    def __str__(self) -> str:
        status = "on" if self.is_enabled else "off"
        return f"{self.user.username} - 2FA {status}"

    # -- secret handling ---------------------------------------------------
    def set_otp_secret(self, secret: str) -> None:
        self.otp_secret = encrypt_secret(secret)

    def get_otp_secret(self) -> str | None:
        if not self.otp_secret:
            return None
        return decrypt_secret(self.otp_secret)

    @property
    def is_configured(self) -> bool:
        return bool(self.otp_secret)


class EnrollmentToken(models.Model):
    """One-time out-of-band token for first-time 2FA enrollment.

    Normal signups do not need a token (the account was just created in the
    same session). Existing/admin accounts created outside the signup flow must
    present a token issued by the ``issue_enrollment_token`` command, so a
    stolen password alone cannot enroll an attacker's authenticator.
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="enrollment_tokens",
    )
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        indexes = [models.Index(fields=["user", "expires_at"])]

    def __str__(self) -> str:
        return f"Enrollment token for {self.user_id}"


class RecoveryCode(models.Model):
    """Hashed one-time recovery codes for users who lose their TOTP app."""

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="recovery_codes",
    )
    code_hash = models.CharField(max_length=64, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        indexes = [models.Index(fields=["user", "used_at"])]

    def __str__(self) -> str:
        return f"Recovery code for {self.user_id}"


class EmailVerification(models.Model):
    """Email ownership proof for account recovery and notifications."""

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="email_verification",
    )
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    verified_at = models.DateTimeField(blank=True, null=True)

    def __str__(self) -> str:
        return f"Email verification for {self.user_id}"


@receiver(post_save, sender=User)
def create_user_two_factor(sender, instance, created, **kwargs):
    """Create an empty 2FA profile for every new user."""
    if created:
        UserTwoFactor.objects.get_or_create(user=instance)
