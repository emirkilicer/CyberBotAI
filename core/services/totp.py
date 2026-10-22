"""TOTP generation, provisioning and verification."""

from __future__ import annotations

import base64
import hmac
import time
from io import BytesIO

import pyotp
import qrcode
from django.conf import settings
from django.db import transaction

from ..models import UserTwoFactor


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(user, secret: str) -> str:
    account_name = user.email or user.username
    return pyotp.TOTP(secret).provisioning_uri(
        name=account_name,
        issuer_name=settings.TOTP_ISSUER,
    )


def qr_data_uri(uri: str) -> str:
    """Render the provisioning URI as an inline PNG data URI."""
    image = qrcode.make(uri)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def normalize_code(raw_code: str | None) -> str:
    code = (raw_code or "").strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return ""
    return code


def verify_code(two_factor: UserTwoFactor, raw_code: str | None) -> bool:
    """Verify a TOTP code and atomically consume its time step.

    A code can only be used once, even within its validity window. The
    ``last_used_step`` update is serialized with ``select_for_update`` so two
    concurrent requests cannot both accept the same code.
    """
    secret = two_factor.get_otp_secret()
    if not secret:
        return False

    code = normalize_code(raw_code)
    if not code:
        return False

    totp = pyotp.TOTP(secret)
    window = max(0, min(int(settings.TWO_FACTOR_VALID_WINDOW), 2))
    current_step = int(time.time()) // totp.interval

    matched_step = None
    for offset in range(-window, window + 1):
        candidate_step = current_step + offset
        if hmac.compare_digest(totp.generate_otp(candidate_step), code):
            matched_step = candidate_step
            break

    if matched_step is None:
        return False

    with transaction.atomic():
        locked = UserTwoFactor.objects.select_for_update().get(pk=two_factor.pk)
        if locked.last_used_step is not None and matched_step <= locked.last_used_step:
            return False
        locked.last_used_step = matched_step
        locked.save(update_fields=["last_used_step", "updated_at"])

    two_factor.last_used_step = matched_step
    return True
