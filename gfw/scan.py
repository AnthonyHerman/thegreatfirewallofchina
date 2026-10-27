"""Find secret-shaped strings in a source tree.

Matches are masked before they are returned so a scan of a dirty tree does
not print the secret back out.
"""

from __future__ import annotations

import re
from pathlib import Path

SECRET = re.compile(
    r"(?i)(?:"
    r"bearer\s+[A-Za-z0-9\-._~+/]{16,}"
    r"|ak_[A-Za-z0-9]{16,}"
    r"|apik[A-Za-z0-9_\-]{16,}"
    r"|(?:sk|gho|ghp|github_pat)_[A-Za-z0-9_\-]{16,}"
    r")"
)

SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "audit",
    "embeddeddolt",
    "dolt",
    "node_modules",
    "dist",
    "build",
    ".egg-info",
}

MAX_BYTES = 1_000_000


def mask(match: str) -> str:
    prefix = match[:4]
    return f"{prefix}…({len(match)})"


def scan_text(text: str) -> list[str]:
    return [mask(match.group(0)) for match in SECRET.finditer(text)]


def redact_text(text: str) -> str:
    return SECRET.sub("[redacted]", text)


def scan_tree(root: Path) -> list[dict[str, str | int]]:
    findings: list[dict[str, str | int]] = []
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS or part.endswith(".egg-info") for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            for masked in scan_text(line):
                findings.append(
                    {
                        "path": str(path.relative_to(root)),
                        "line": number,
                        "match": masked,
                    }
                )
    return findings
