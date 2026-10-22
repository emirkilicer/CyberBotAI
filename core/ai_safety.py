"""Lightweight guardrails for the AI chat endpoint.

This is not a complete moderation system. It blocks obvious prompt-extraction
and jailbreak attempts, rejects control characters, and normalizes model output.
A production deployment should add a dedicated moderation service and an
evaluation set.
"""

from __future__ import annotations

import re

from django.conf import settings

_BLOCKED_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore (all )?(the )?(previous|prior|above) (instructions|rules|prompts)",
        r"disregard (all )?(the )?(previous|prior|above) (instructions|rules|prompts)",
        r"(reveal|show|print|repeat) (me )?(your |the )?(system )?(prompt|instructions)",
        r"system prompt",
        r"jailbreak",
        r"\bdan mode\b",
        r"developer mode",
        r"pretend (you are|to be) (an? )?(unrestricted|uncensored)",
    )
]

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def screen_input(message: str) -> tuple[bool, str]:
    if not message or not message.strip():
        return False, "Message cannot be empty."
    if len(message) > settings.CHAT_MAX_MESSAGE_LENGTH:
        return False, "Message is too long."
    if _CONTROL_CHARS.search(message):
        return False, "Message contains invalid control characters."

    for pattern in _BLOCKED_PATTERNS:
        if pattern.search(message):
            return False, "Message blocked by the prompt-injection policy."

    return True, ""


def sanitize_output(text: str) -> str:
    if not isinstance(text, str):
        return ""
    cleaned = _CONTROL_CHARS.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    cleaned = cleaned.strip()
    max_length = getattr(settings, "CHAT_MAX_OUTPUT_LENGTH", 8000)
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length].rstrip()
    return cleaned
