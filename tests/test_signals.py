from pathlib import Path

from gfw.config import default_config
from gfw.signals import derive_signals, floor_action, policy_hits
from gfw.trace import load_trace

FIXTURES = Path(__file__).resolve().parents[1] / "gfw" / "fixtures"


def _floor(name: str) -> tuple[str, set[str]]:
    trace = load_trace(FIXTURES / name)
    hits = policy_hits(trace, default_config())
    signals = derive_signals(trace, hits)
    return floor_action(hits, signals), {item.name for item in signals}


def test_phone_home_fixture_blocks():
    floor, names = _floor("phone_home.json")
    assert floor == "block"
    assert "recon_then_egress" in names
    assert "callback_egress" in names
    assert "stated_no_tools" in names


def test_recon_only_is_review():
    floor, names = _floor("recon_only.json")
    assert floor == "review"
    assert names == {"env_recon"}


def test_local_inference_is_allow():
    floor, names = _floor("local_inference.json")
    assert floor == "allow"
    assert names == set()


def test_stated_no_tools_without_egress_is_review():
    trace = {
        "reasoning": "I will not use tools.",
        "actions": [{"kind": "read_file", "path": "/tmp/notes.txt"}],
    }
    hits = policy_hits(trace, default_config())
    signals = derive_signals(trace, hits)
    assert floor_action(hits, signals) == "review"
    assert signals[0].name == "stated_no_tools"
