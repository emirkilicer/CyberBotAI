"""One-time 2FA enrollment tokens.

Tokens are high-entropy random values. Only a SHA-256 hash is stored, so a
database leak does not reveal usable enrollment links.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from django.utils import timezone

from ..models import EnrollmentToken

DEFAULT_TTL_SECONDS = 15 * 60


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def issue_token(user, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    """Create a fresh token and invalidate previous unused tokens."""
    EnrollmentToken.objects.filter(user=user, used_at__isnull=True).delete()
    raw_token = secrets.token_urlsafe(32)
    EnrollmentToken.objects.create(
        user=user,
        token_hash=hash_token(raw_token),
        expires_at=timezone.now() + timedelta(seconds=ttl_seconds),
    )
    return raw_token


def validate_token(user, raw_token: str | None):
    if not raw_token:
        return None
    return EnrollmentToken.objects.filter(
        user=user,
        token_hash=hash_token(raw_token),
        used_at__isnull=True,
        expires_at__gt=timezone.now(),
    ).first()


def validate_token_hash(user, token_hash: str | None):
    if not token_hash:
        return None
    return EnrollmentToken.objects.filter(
        user=user,
        token_hash=token_hash,
        used_at__isnull=True,
        expires_at__gt=timezone.now(),
    ).first()


def consume_token(token: EnrollmentToken | None) -> None:
    if token is None:
        return
    EnrollmentToken.objects.filter(pk=token.pk, used_at__isnull=True).update(
        used_at=timezone.now()
    )
