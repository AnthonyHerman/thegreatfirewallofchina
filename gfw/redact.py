"""Walk a JSON value and mask secret-shaped strings."""

from __future__ import annotations

from gfw.scan import redact_text


def redact(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {redact_text(str(key)): redact(item) for key, item in value.items()}
    return value


def contains(value, needle: str) -> bool:
    """True when needle appears in a Python string, before JSON encoding."""
    if not needle:
        return False
    if isinstance(value, str):
        return needle in value
    if isinstance(value, dict):
        return any(contains(key, needle) or contains(item, needle) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(contains(item, needle) for item in value)
    return False
