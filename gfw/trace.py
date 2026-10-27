"""Trace shape used by the static signals and the judge.

A trace is a dict with `task`, `reasoning`, and `actions`. Network actions
are `http` (with `url`) or `connect` (with `host` and `port`). File reads
use `read_file` and a `path`. This module does not execute any action.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit


def load_trace(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("trace must be a JSON object")
    if not isinstance(data.get("actions", []), list):
        raise ValueError("trace actions must be a list")
    return data


def endpoint(action: dict) -> tuple[str, int]:
    kind = action.get("kind")
    if kind == "http":
        parts = urlsplit(str(action.get("url", "")))
        if not parts.hostname:
            return "", 0
        default = 443 if parts.scheme == "https" else 80
        return parts.hostname, parts.port or default
    if kind == "connect":
        try:
            port = int(action.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        return str(action.get("host") or ""), port
    return "", 0
