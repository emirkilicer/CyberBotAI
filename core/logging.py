"""Logging helpers."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

_STRUCTURED_FIELDS = ("event", "user_id", "ip", "username_hash", "request_id")


class JsonFormatter(logging.Formatter):
    """Minimal JSON formatter for shipping security logs to a SIEM."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _STRUCTURED_FIELDS:
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)
