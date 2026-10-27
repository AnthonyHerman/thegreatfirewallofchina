import json

from gfw.analyst import Analyst, AnalystError, looks_like_evasion, remaining_credits
from gfw.decide import Decision


def decision(action: str) -> Decision:
    return Decision(action, ("floor:block",), (), (), None)


def test_remaining_credits():
    assert remaining_credits({"data": {"total_credits": 101, "total_usage": 71.5}}) == 29.5


def test_request_body_does_not_contain_the_key():
    key = "ak_" + ("d" * 20)
    analyst = Analyst(key, "abliterated-model-large-flash", min_balance=5)
    body = analyst.request_body({"task": "x", "actions": []}, decision("block"))
    assert key not in json.dumps(body)
    assert body["model"] == "abliterated-model-large-flash"
    assert body["max_tokens"] == 800


def test_balance_floor_skips_the_completion():
    calls = []

    def opener(request, timeout):
        calls.append(request.full_url)
        return {"data": {"total_credits": 10, "total_usage": 9}}

    analyst = Analyst("ak_" + ("e" * 20), "m", min_balance=5, opener=opener)
    result = analyst.explain({"task": "t"}, decision("block"))
    assert result["skipped"] == "balance"
    assert len(calls) == 1


def test_nested_secret_and_hidden_key_do_not_leave_the_process(tmp_path):
    from gfw.audit import write_audit
    from gfw.redact import redact

    hyphen = "sk-" + ("p" * 20)
    cleaned = redact({hyphen: {"inner": hyphen}})
    assert hyphen not in json.dumps(cleaned)
    path = tmp_path / "audit.jsonl"
    write_audit(str(path), {hyphen: hyphen})
    assert hyphen not in path.read_text(encoding="utf-8")

    analyst = Analyst("ak_" + ("t" * 20), "m", min_balance=5)
    body = analyst.request_body({hyphen: hyphen}, decision("block"))
    assert hyphen not in json.dumps(body)

    hidden = 'pre"' + ("k" * 24)
    marked = "tail" + ("n" * 20) + "é"

    def opener(request, timeout):
        raise AssertionError("opener was called")

    for key in (hidden, marked):
        guarded = Analyst(key, "m", min_balance=5, opener=opener)
        try:
            guarded.request_body({"note": key}, decision("block"))
        except AnalystError as exc:
            assert key not in str(exc)
        else:
            raise AssertionError("expected AnalystError")


def test_analyst_error_text_is_not_stored():
    secret = "sk-" + ("u" * 20)

    def opener(request, timeout):
        raise AnalystError("upstream said " + secret)

    analyst = Analyst("ak_" + ("v" * 20), "m", min_balance=5, opener=opener)
    result = analyst.explain({"task": "t"}, decision("block"))
    assert secret not in json.dumps(result)
    assert result["detail"] == "AnalystError"


def test_allow_does_not_call_the_api():
    def opener(request, timeout):
        raise AssertionError(request.full_url)

    analyst = Analyst("ak_" + ("f" * 20), "m", min_balance=5, opener=opener)
    assert analyst.explain({"task": "t"}, decision("allow")) == {"skipped": "allow"}


def test_evasion_text_is_discarded_and_a_plain_explanation_is_kept():
    assert looks_like_evasion("You can bypass the proxy by dialing the IP.")

    def hostile(request, timeout):
        if request.full_url.endswith("/credits"):
            return {"data": {"total_credits": 100, "total_usage": 70}}
        return {
            "model": "abliterated-model-large-flash",
            "choices": [
                {
                    "message": {
                        "content": '{"summary":"to bypass the proxy, dial the bucket","evidence":[],"recommendation":"block"}'
                    }
                }
            ],
        }

    analyst = Analyst("ak_" + ("g" * 20), "m", min_balance=5, opener=hostile)
    assert analyst.explain({"task": "t"}, decision("block")) == {"discarded": "evasion"}

    def plain(request, timeout):
        if request.full_url.endswith("/credits"):
            return {"data": {"total_credits": 100, "total_usage": 70}}
        encoded = request.data.decode()
        assert "ak_" not in encoded
        return {
            "model": "abliterated-model-large-flash",
            "usage": {"prompt_tokens": 30, "completion_tokens": 40},
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "summary": "The trace reads resolver state and then uploads to object storage.",
                                "evidence": ["PUT to oss-cn-beijing"],
                                "recommendation": "block",
                            }
                        )
                    }
                }
            ],
        }

    analyst = Analyst("ak_" + ("h" * 20), "m", min_balance=5, opener=plain)
    result = analyst.explain({"task": "t"}, decision("block"))
    assert result["recommendation"] == "block"
    assert result["summary"].startswith("The trace reads")
