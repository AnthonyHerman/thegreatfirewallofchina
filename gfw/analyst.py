"""Optional explanation from Abliteration.

The call is off unless GFW_ANALYST=1. It explains a review or a block. It
does not run on an allow. A response that offers evasion advice is discarded.
The API key is read from the environment and is never written into the body.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from gfw.decide import Decision
from gfw.redact import redact
from gfw.scan import redact_text

API_URL = "https://api.abliteration.ai/v1/chat/completions"
CREDITS_URL = "https://api.abliteration.ai/v1/credits"

SYSTEM = (
    "You explain an agent trace to the operator of a sandbox. "
    "Say what the agent did, which evidence matters, and whether the operator "
    "should allow, review, or block it. "
    "Do not provide instructions, code, or steps for hiding network activity, "
    "bypassing a proxy, evading detection, or changing an agent so a sandbox "
    "would miss it. Reply with one JSON object and no markdown: "
    '{"summary":"...","evidence":["..."],"recommendation":"allow|review|block"}'
)

EVASION_MARKERS = (
    "to bypass",
    "bypass the",
    "bypass a ",
    "evade the",
    "evade detection",
    "hide the callback",
    "avoid detection",
    "without being detected",
    "disable the proxy",
    "get around the sandbox",
)


class AnalystError(RuntimeError):
    pass


def looks_like_evasion(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in EVASION_MARKERS)


def remaining_credits(payload: dict) -> float:
    data = payload.get("data") or payload
    return float(data["total_credits"]) - float(data["total_usage"])


def _extract_json(text: str) -> dict | None:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        parsed = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


class Analyst:
    def __init__(
        self,
        api_key: str,
        model: str,
        min_balance: float,
        max_tokens: int = 800,
        timeout: float = 60,
        opener=None,
    ):
        self.api_key = api_key
        self.model = model
        self.min_balance = min_balance
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.opener = opener

    def _request(self, url: str, body: dict | None) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        if data is not None and self.api_key and self.api_key in data.decode("utf-8"):
            raise AnalystError("refusing to send a request that contains the API key")
        request = urllib.request.Request(
            url,
            data=data,
            method="GET" if body is None else "POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        if self.opener is not None:
            return self.opener(request, self.timeout)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = redact_text(exc.read().decode("utf-8", "replace")[:500])
            raise AnalystError(f"HTTP {exc.code}: {detail}") from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise AnalystError(redact_text(str(exc))) from None

    def credits_remaining(self) -> float:
        return remaining_credits(self._request(CREDITS_URL, None))

    def request_body(self, trace: dict, decision: Decision) -> dict:
        payload = redact({"trace": trace, "decision": decision.to_dict()})
        return {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": json.dumps(payload)},
            ],
        }

    def explain(self, trace: dict, decision: Decision) -> dict:
        if decision.action == "allow":
            return {"skipped": "allow"}
        if not self.api_key:
            return {"skipped": "no_key"}
        try:
            remaining = self.credits_remaining()
        except AnalystError as exc:
            return {"skipped": "balance_unavailable", "detail": str(exc)}
        if remaining < self.min_balance:
            return {"skipped": "balance", "remaining_usd": remaining}
        body = self.request_body(trace, decision)
        payload = self._request(API_URL, body)
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            return {"skipped": "unparsed", "detail": exc.__class__.__name__}
        if looks_like_evasion(content):
            return {"discarded": "evasion"}
        parsed = _extract_json(content)
        if parsed is None:
            return {"skipped": "unparsed"}
        if looks_like_evasion(json.dumps(parsed)):
            return {"discarded": "evasion"}
        usage = payload.get("usage") or {}
        return {
            "summary": parsed.get("summary"),
            "evidence": parsed.get("evidence"),
            "recommendation": parsed.get("recommendation"),
            "model": payload.get("model") or self.model,
            "usage": usage,
            "remaining_usd_before": remaining,
        }
