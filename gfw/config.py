"""Operator configuration. Keys are never read from this file."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class Config:
    allow_hosts: frozenset[str]
    allow_suffixes: frozenset[str]
    extra_deny_suffixes: frozenset[str]
    allow_private: bool
    jev_model: str
    noul_block: float
    noul_review: float
    choice_confidence_min: float
    analyst: bool
    analyst_min_balance: float
    analyst_model: str
    analyst_max_tokens: int
    audit_path: str

    def with_overrides(self, data: dict) -> Config:
        updates = {}
        for name in ("allow_hosts", "allow_suffixes", "extra_deny_suffixes"):
            if name in data:
                updates[name] = frozenset(str(item).lower() for item in data[name])
        if "allow_private" in data:
            updates["allow_private"] = bool(data["allow_private"])
        for name in ("jev_model", "analyst_model", "audit_path"):
            if name in data and data[name]:
                updates[name] = str(data[name])
        for name in ("noul_block", "noul_review", "choice_confidence_min", "analyst_min_balance"):
            if name in data:
                updates[name] = float(data[name])
        if "analyst_max_tokens" in data:
            updates["analyst_max_tokens"] = int(data["analyst_max_tokens"])
        if "analyst" in data:
            updates["analyst"] = bool(data["analyst"])
        return replace(self, **updates)


def default_config() -> Config:
    analyst_flag = os.environ.get("GFW_ANALYST", "")
    try:
        floor = float(os.environ.get("GFW_ANALYST_MIN_BALANCE", "5"))
    except ValueError:
        floor = 5.0
    return Config(
        allow_hosts=frozenset({"localhost", "127.0.0.1", "::1"}),
        allow_suffixes=frozenset(),
        extra_deny_suffixes=frozenset(),
        allow_private=False,
        jev_model=os.environ.get("GFW_JEV_MODEL", "jev-latest"),
        noul_block=0.7,
        noul_review=0.3,
        choice_confidence_min=0.6,
        analyst=analyst_flag == "1",
        analyst_min_balance=floor,
        analyst_model=os.environ.get("GFW_ANALYST_MODEL", "abliterated-model-large-flash"),
        analyst_max_tokens=800,
        audit_path=os.environ.get("GFW_AUDIT", "audit/decisions.jsonl"),
    )


def load_config(path: str | Path | None = None) -> Config:
    config = default_config()
    if not path:
        return config
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return config.with_overrides(data)
