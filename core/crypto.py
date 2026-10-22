"""Encryption helpers for sensitive data at rest.

TOTP secrets must be readable by the server (unlike passwords), so they are
encrypted with Fernet (AES-128-CBC + HMAC-SHA256). The key is supplied through
``TOTP_ENCRYPTION_KEY``. Multiple comma-separated keys are supported for
rotation: the first key encrypts, all keys can decrypt.
"""

from __future__ import annotations

import base64
import hashlib
import re
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

_LEGACY_TOTP_RE = re.compile(r"^[A-Z2-7]{16,64}$")
_FERNET_PREFIX = "gAAAA"


def _derive_dev_key(secret_key: str) -> bytes:
    """Deterministic development key derived from SECRET_KEY.

    Only used when DEBUG is on and no explicit key is configured. Never use
    this in production: rotating SECRET_KEY would make TOTP secrets unreadable.
    """
    digest = hashlib.sha256(f"cyberbot-totp:{secret_key}".encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _configured_keys() -> list[bytes]:
    raw = (getattr(settings, "TOTP_ENCRYPTION_KEY", "") or "").strip()
    if raw:
        keys = [part.strip().encode() for part in raw.split(",") if part.strip()]
        if not keys:
            raise ImproperlyConfigured("TOTP_ENCRYPTION_KEY is empty.")
        return keys

    if settings.DEBUG:
        return [_derive_dev_key(settings.SECRET_KEY)]

    raise ImproperlyConfigured(
        "TOTP_ENCRYPTION_KEY is required when DEBUG is off. Generate one with: "
        "python -c \"from cryptography.fernet import Fernet; "
        "print(Fernet.generate_key().decode())\""
    )


@lru_cache(maxsize=1)
def _fernet() -> MultiFernet:
    keys = _configured_keys()
    try:
        return MultiFernet([Fernet(key) for key in keys])
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured(
            "TOTP_ENCRYPTION_KEY is not a valid Fernet key. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        ) from exc


def is_encrypted(value: str | None) -> bool:
    return bool(value) and value.startswith(_FERNET_PREFIX)


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        raise ValueError("Cannot encrypt an empty TOTP secret.")
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str, *, allow_legacy: bool = True) -> str:
    """Decrypt a TOTP secret.

    ``allow_legacy`` accepts base32 values written before encryption was
    introduced. The data migration encrypts them, so this path exists only to
    keep upgrades and rollbacks safe.
    """
    if is_encrypted(value):
        try:
            return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise ImproperlyConfigured(
                "TOTP secret could not be decrypted. Check TOTP_ENCRYPTION_KEY."
            ) from exc

    if allow_legacy and _LEGACY_TOTP_RE.fullmatch(value or ""):
        return value

    raise ImproperlyConfigured("Stored TOTP secret is neither encrypted nor valid base32.")
