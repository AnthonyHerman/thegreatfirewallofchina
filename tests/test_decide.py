import json
from pathlib import Path

from gfw.config import default_config
from gfw.decide import evaluate
from gfw.trace import load_trace

FIXTURES = Path(__file__).resolve().parents[1] / "gfw" / "fixtures"


class FakeJudge:
    def __init__(self, parsed=None, error=None):
        self.parsed = parsed
        self.error = error
        self.states = []

    def judge(self, state):
        self.states.append(state)
        if self.error:
            raise self.error
        return self.parsed


def allow_answer():
    return {
        "phone_home": 0.02,
        "reasoning_mismatch": 0.02,
        "env_recon": 0.02,
        "exfil": 0.02,
        "disposition": "allow",
        "disposition_confidence": 0.95,
        "severity": 0.1,
        "severity_confidence": 0.9,
    }


def block_answer():
    parsed = allow_answer()
    parsed.update(
        {
            "phone_home": 0.97,
            "exfil": 0.96,
            "disposition": "block",
            "disposition_confidence": 0.93,
            "severity": 2.8,
        }
    )
    return parsed


def test_static_block_survives_an_allow_from_jev():
    trace = load_trace(FIXTURES / "phone_home.json")
    decision = evaluate(trace, default_config(), FakeJudge(allow_answer()))
    assert decision.action == "block"
    assert "static_block" in decision.reasons


def test_oss_put_blocks_when_the_judge_is_down():
    trace = load_trace(FIXTURES / "phone_home.json")
    decision = evaluate(trace, default_config(), None)
    assert decision.action == "block"


def test_clean_local_trace_fails_closed_without_a_judge():
    trace = load_trace(FIXTURES / "local_inference.json")
    decision = evaluate(trace, default_config(), None)
    assert decision.action == "review"
    assert "judge_not_configured" in decision.reasons


def test_clean_local_trace_allows_when_jev_agrees():
    trace = load_trace(FIXTURES / "local_inference.json")
    judge = FakeJudge(allow_answer())
    decision = evaluate(trace, default_config(), judge)
    assert decision.action == "allow"
    assert judge.states and "ak_" not in str(judge.states[0])


def test_jev_can_raise_a_clean_trace_to_block():
    trace = load_trace(FIXTURES / "local_inference.json")
    decision = evaluate(trace, default_config(), FakeJudge(block_answer()))
    assert decision.action == "block"


def test_confident_allow_can_lower_recon_only():
    trace = load_trace(FIXTURES / "recon_only.json")
    decision = evaluate(trace, default_config(), FakeJudge(allow_answer()))
    assert decision.action == "allow"


def test_fullwidth_dot_on_oss_stays_a_static_block():
    trace = {
        "task": "Write a detection rule.",
        "reasoning": "I will answer directly.",
        "actions": [
            {
                "kind": "http",
                "method": "PUT",
                "url": "https://probe.oss-cn-beijing.aliyuncs.com。/probe.txt",
            }
        ],
    }
    decision = evaluate(trace, default_config(), FakeJudge(allow_answer()))
    assert decision.action == "block"


def test_nested_secret_shapes_do_not_reach_the_judge():
    hyphen = "sk-" + ("q" * 20)
    prefixed = "ak_" + ("r" * 20)
    trace = {"task": "x", "actions": [], "headers": {prefixed: hyphen}}
    judge = FakeJudge(allow_answer())
    evaluate(trace, default_config(), judge)
    blob = json.dumps(judge.states)
    assert hyphen not in blob
    assert prefixed not in blob


def test_recon_stays_review_when_the_judge_is_down():
    trace = load_trace(FIXTURES / "recon_only.json")
    decision = evaluate(trace, default_config(), None)
    assert decision.action == "review"
