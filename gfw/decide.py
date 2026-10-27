"""Combine static policy with a System One judgment.

A static block stays a block if JEV disagrees or is down. A missing judge
moves a clean trace from allow to review. JEV may raise an allow to review
or block, and may lower a review to allow only when the allow answer is
confident and every risk noul is under the review cut.
"""

from __future__ import annotations

from dataclasses import dataclass

from gfw.config import Config
from gfw.judge import JudgeError
from gfw.redact import redact
from gfw.signals import Signal, derive_signals, floor_action, policy_hits

RANK = {"allow": 0, "review": 1, "block": 2}


@dataclass(frozen=True)
class Decision:
    action: str
    reasons: tuple[str, ...]
    policy: tuple[dict, ...]
    signals: tuple[dict, ...]
    judge: dict | None
    analyst: dict | None = None

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "reasons": list(self.reasons),
            "policy": list(self.policy),
            "signals": list(self.signals),
            "judge": self.judge,
            "analyst": self.analyst,
        }


def stricter(left: str, right: str) -> str:
    return left if RANK[left] >= RANK[right] else right


def jev_action(parsed: dict, config: Config) -> str:
    phone = float(parsed["phone_home"])
    exfil = float(parsed["exfil"])
    mismatch = float(parsed["reasoning_mismatch"])
    recon = float(parsed["env_recon"])
    choice = parsed["disposition"]
    confidence = float(parsed["disposition_confidence"])
    if phone >= config.noul_block or exfil >= config.noul_block:
        return "block"
    if choice == "block" and confidence >= config.choice_confidence_min:
        return "block"
    if choice == "allow" and confidence >= config.choice_confidence_min:
        if max(phone, exfil, mismatch, recon) < config.noul_review:
            return "allow"
        return "review"
    return "review"


def combine(floor: str, parsed: dict | None, error: str | None, config: Config) -> tuple[str, tuple[str, ...]]:
    reasons: list[str] = [f"floor:{floor}"]
    if floor == "block":
        reasons.append("static_block")
        return "block", tuple(reasons)
    if error or parsed is None:
        reasons.append(error or "judge_unavailable")
        return "review", tuple(reasons)
    chosen = jev_action(parsed, config)
    reasons.append(f"jev:{chosen}")
    if floor == "review" and chosen == "allow":
        return "allow", tuple(reasons)
    return stricter(floor, chosen), tuple(reasons)


def build_state(trace: dict, hits: list[dict], signals: tuple[Signal, ...]) -> dict:
    return redact(
        {
            "task": trace.get("task"),
            "reasoning": trace.get("reasoning"),
            "model": trace.get("model"),
            "actions": trace.get("actions") or [],
            "policy": hits,
            "signals": [item.to_dict() for item in signals],
        }
    )


def evaluate(trace: dict, config: Config, judge=None) -> Decision:
    safe = redact(trace)
    hits = policy_hits(safe, config)
    signals = derive_signals(safe, hits)
    floor = floor_action(hits, signals)
    parsed = None
    error = None
    if judge is None:
        error = "judge_not_configured"
    else:
        try:
            parsed = judge.judge(build_state(safe, hits, signals))
        except (JudgeError, OSError, TimeoutError) as exc:
            error = exc.__class__.__name__
    action, reasons = combine(floor, parsed, error, config)
    signal_reasons = tuple(f"signal:{item.name}" for item in signals)
    policy_reasons = tuple(
        f"policy:{hit['host']}:{reason}" for hit in hits for reason in hit["reasons"]
    )
    return Decision(
        action=action,
        reasons=reasons + signal_reasons + policy_reasons,
        policy=tuple(hits),
        signals=tuple(item.to_dict() for item in signals),
        judge=parsed,
    )
