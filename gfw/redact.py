"""Walk a JSON value and mask secret-shaped strings."""

from __future__ import annotations

from gfw.scan import redact_text


def redact(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {str(key): redact(item) for key, item in value.items()}
    return value
