"""Append-only decision log. Records are redacted before they hit disk."""

from __future__ import annotations

import json
from pathlib import Path

from gfw.redact import redact


def write_audit(path: str, record: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(redact(record), sort_keys=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
