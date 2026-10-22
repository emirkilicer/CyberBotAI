"""One-time recovery codes.

Codes are shown once at enrollment time and stored only as SHA-256 hashes.
Each code is 80 bits of entropy, so a fast hash is sufficient and keeps
verification simple. Used codes are never reissued.
"""

from __future__ import annotations

import hashlib
import secrets

from django.db import transaction
from django.utils import timezone

from ..models import RecoveryCode

CODE_COUNT = 10


def _normalize(raw_code: str) -> str:
    return "".join(ch for ch in (raw_code or "").upper() if ch.isalnum())


def _hash(raw_code: str) -> str:
    return hashlib.sha256(_normalize(raw_code).encode("utf-8")).hexdigest()


def generate_codes(user, count: int = CODE_COUNT) -> list[str]:
    """Replace all outstanding codes and return the plaintext list once."""
    RecoveryCode.objects.filter(user=user).delete()
    codes = []
    for _ in range(count):
        raw_code = "-".join(secrets.token_hex(2).upper() for _ in range(5))
        codes.append(raw_code)
        RecoveryCode.objects.create(user=user, code_hash=_hash(raw_code))
    return codes


def verify_code(user, raw_code: str) -> bool:
    normalized = _normalize(raw_code)
    if len(normalized) < 16:
        return False

    code_hash = _hash(raw_code)
    with transaction.atomic():
        code = (
            RecoveryCode.objects.select_for_update()
            .filter(user=user, code_hash=code_hash, used_at__isnull=True)
            .first()
        )
        if code is None:
            return False
        code.used_at = timezone.now()
        code.save(update_fields=["used_at"])
    return True


def remaining_count(user) -> int:
    return RecoveryCode.objects.filter(user=user, used_at__isnull=True).count()
