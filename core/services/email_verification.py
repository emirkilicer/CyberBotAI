"""Email ownership verification."""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

from ..models import EmailVerification

DEFAULT_TTL_SECONDS = 24 * 60 * 60


def _hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def issue_token(user, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    raw_token = secrets.token_urlsafe(32)
    EmailVerification.objects.update_or_create(
        user=user,
        defaults={
            "token_hash": _hash(raw_token),
            "expires_at": timezone.now() + timedelta(seconds=ttl_seconds),
            "verified_at": None,
        },
    )
    return raw_token


def send_verification_email(request, user) -> None:
    if not user.email:
        return
    raw_token = issue_token(user)
    verification_url = request.build_absolute_uri(
        reverse("verify_email", kwargs={"token": raw_token})
    )
    subject = "CYBERBOT - Verify your email address"
    message = render_to_string(
        "email_verification_email.txt",
        {"user": user, "verification_url": verification_url},
    )
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])


def verify_token(raw_token: str):
    token = (
        EmailVerification.objects.select_related("user")
        .filter(
            token_hash=_hash(raw_token or ""),
            verified_at__isnull=True,
            expires_at__gt=timezone.now(),
            user__is_active=True,
        )
        .first()
    )
    if token is None:
        return None
    token.verified_at = timezone.now()
    token.save(update_fields=["verified_at"])
    return token.user


def is_verified(user) -> bool:
    return EmailVerification.objects.filter(
        user=user, verified_at__isnull=False
    ).exists()
