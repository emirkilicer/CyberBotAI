"""Cache-backed throttling helpers.

With the default LocMemCache the counters are per process. Set ``REDIS_URL``
when running more than one worker so limits are shared.
"""

from __future__ import annotations

import hashlib
import time

from django.core.cache import cache


def client_ip(request) -> str:
    # REMOTE_ADDR is used on purpose: X-Forwarded-For is attacker controlled
    # unless a trusted proxy is configured in front of the application.
    return request.META.get("REMOTE_ADDR") or "unknown"


def _digest(identifier: object) -> str:
    return hashlib.sha256(str(identifier).encode("utf-8")).hexdigest()[:32]


def _bucket_key(scope: str, identifier: object) -> str:
    return f"rl:{scope}:{_digest(identifier)}"


def _lock_key(scope: str, identifier: object) -> str:
    return f"rl:{scope}:{_digest(identifier)}:lock"


def allow(scope: str, identifier: object, *, limit: int, window: int) -> bool:
    """Fixed-window rate limit. Returns False when the limit is exceeded."""
    if limit <= 0:
        return True
    bucket = int(time.time() // window)
    key = f"{_bucket_key(scope, identifier)}:{bucket}"
    if cache.add(key, 1, timeout=window):
        return True
    try:
        return cache.incr(key) <= limit
    except ValueError:
        # Key expired between add and incr.
        cache.set(key, 1, timeout=window)
        return True


def is_locked(scope: str, identifier: object) -> bool:
    return bool(cache.get(_lock_key(scope, identifier)))


def record_failure(
    scope: str,
    identifier: object,
    *,
    limit: int,
    window: int,
    lockout: int,
) -> int:
    """Increment a failure counter and lock the identifier after ``limit``."""
    key = _bucket_key(scope, identifier)
    if cache.add(key, 1, timeout=window):
        count = 1
    else:
        try:
            count = cache.incr(key)
        except ValueError:
            cache.set(key, 1, timeout=window)
            count = 1

    if count >= limit:
        cache.set(_lock_key(scope, identifier), 1, timeout=lockout)
    return count


def clear_failures(scope: str, identifier: object) -> None:
    cache.delete_many([_bucket_key(scope, identifier), _lock_key(scope, identifier)])
