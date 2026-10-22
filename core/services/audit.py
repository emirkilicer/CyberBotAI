"""Minimal audit logging for authentication events.

Events intentionally avoid secrets, raw usernames and TOTP codes. A real
deployment should ship these records to an append-only SIEM.
"""

from __future__ import annotations

import hashlib
import logging

from .ratelimit import client_ip

logger = logging.getLogger("core.audit")


def _username_hash(username: str | None) -> str:
    if not username:
        return "-"
    return hashlib.sha256(username.lower().encode("utf-8")).hexdigest()[:16]


def log_event(
    event: str,
    *,
    request=None,
    user=None,
    username: str | None = None,
    level: int | None = None,
    **fields,
) -> None:
    user_id = getattr(user, "pk", None) or "-"
    ip = client_ip(request) if request is not None else "-"
    if level is None:
        level = (
            logging.WARNING
            if event.endswith(("_locked", "_blocked", "_rate_limited"))
            else logging.INFO
        )

    extra = {
        "event": event,
        "user_id": str(user_id),
        "ip": ip,
        "username_hash": _username_hash(username),
    }
    extra.update({key: str(value) for key, value in fields.items()})

    rendered_fields = " ".join(f"{key}={value}" for key, value in fields.items())
    logger.log(
        level,
        "event=%s user_id=%s ip=%s username_hash=%s %s",
        event,
        user_id,
        ip,
        extra["username_hash"],
        rendered_fields,
        extra=extra,
    )
