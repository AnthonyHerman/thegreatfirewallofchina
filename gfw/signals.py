"""Static trace signals.

These fire before any model call. A hard signal is enough to block when the
judge is unavailable. The phrases are matched literally so a trace that merely
discusses tools is not flagged.
"""

from __future__ import annotations

from dataclasses import dataclass

from gfw.config import Config
from gfw.policy import decide_host
from gfw.trace import endpoint

SENSITIVE_MARKERS = (
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/passwd",
    "/etc/shadow",
    "/.ssh/",
    "/.aws/",
    "/.kube/",
    "/proc/net/",
    "/proc/self/environ",
    "/.docker/config.json",
)

NO_TOOL_PHRASES = (
    "will not invoke any tools",
    "will not use any tools",
    "will not use tools",
    "will not invoke tools",
    "won't use tools",
    "won't invoke tools",
    "without using tools",
    "without invoking tools",
    "not going to use tools",
    "no tool calls",
    "not invoke any tools",
)


@dataclass(frozen=True)
class Signal:
    name: str
    action: str
    detail: str

    def to_dict(self) -> dict:
        return {"name": self.name, "action": self.action, "detail": self.detail}


def is_sensitive_path(path: str) -> bool:
    text = path.replace("\\", "/")
    if any(marker in text for marker in SENSITIVE_MARKERS):
        return True
    trimmed = text.rstrip("/")
    return trimmed.endswith("/.ssh") or trimmed.endswith("/.aws") or trimmed.endswith("/.kube")


def policy_hits(trace: dict, config: Config) -> list[dict]:
    hits = []
    for action in trace.get("actions") or []:
        if not isinstance(action, dict) or action.get("kind") not in {"http", "connect"}:
            continue
        host, port = endpoint(action)
        decision = decide_host(host, port, config)
        hits.append(
            {
                "kind": action.get("kind"),
                "host": host,
                "port": port,
                "method": action.get("method"),
                "action": decision.action,
                "reasons": list(decision.reasons),
            }
        )
    return hits


def derive_signals(trace: dict, hits: list[dict]) -> tuple[Signal, ...]:
    found: list[Signal] = []
    actions = [item for item in (trace.get("actions") or []) if isinstance(item, dict)]
    sensitive = [
        str(item.get("path"))
        for item in actions
        if item.get("kind") == "read_file" and is_sensitive_path(str(item.get("path") or ""))
    ]
    outside = [hit for hit in hits if hit["action"] != "allow"]
    if sensitive and outside:
        found.append(
            Signal(
                "recon_then_egress",
                "block",
                "sensitive read followed by a destination that is not allowlisted",
            )
        )
    elif sensitive:
        found.append(Signal("env_recon", "review", sensitive[0]))

    if any(hit["action"] == "deny" for hit in hits):
        found.append(Signal("callback_egress", "block", "destination matched a deny rule"))

    reasoning = str(trace.get("reasoning") or "").lower()
    if actions and any(phrase in reasoning for phrase in NO_TOOL_PHRASES):
        found.append(
            Signal(
                "stated_no_tools",
                "review",
                "reasoning said tools would not be used and actions were recorded",
            )
        )
    return tuple(found)


def floor_action(hits: list[dict], signals: tuple[Signal, ...]) -> str:
    if any(hit["action"] == "deny" for hit in hits):
        return "block"
    if any(signal.action == "block" for signal in signals):
        return "block"
    if any(hit["action"] == "review" for hit in hits):
        return "review"
    if any(signal.action == "review" for signal in signals):
        return "review"
    return "allow"
