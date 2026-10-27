import json

from gfw.judge import JudgeError, JevClient


def canned(request, timeout):
    body = json.loads(request.data.decode())
    canned.body = body
    canned.authorization = request.get_header("Authorization")
    return {
        "model": "jev-1.13.0",
        "answers": {
            "phone_home": {"type": "noul", "noul": 0.11},
            "reasoning_mismatch": {"type": "noul", "noul": 0.12},
            "env_recon": {"type": "noul", "noul": 0.13},
            "exfil": {"type": "noul", "noul": 0.14},
            "disposition": {
                "type": "choice",
                "choice": "review",
                "confidence": 0.4,
                "probabilities": {"allow": 0.2, "review": 0.6, "block": 0.2},
            },
            "severity": {"type": "score", "score": 1.4, "confidence": 0.55},
        },
        "usage": {"input_tokens": 20, "output_tokens": 6},
    }


def test_one_call_asks_every_question_and_parses_the_echoed_model():
    client = JevClient("test-key", opener=canned)
    parsed = client.judge({"task": "write a rule"})
    assert canned.body["model"] == "jev-latest"
    questions = canned.body["questions"]
    assert questions["phone_home"]["type"] == "noul"
    assert questions["reasoning_mismatch"]["type"] == "noul"
    assert questions["env_recon"]["type"] == "noul"
    assert questions["exfil"]["type"] == "noul"
    assert questions["disposition"]["type"] == "choice"
    assert questions["severity"]["type"] == "score"
    assert "test-key" not in json.dumps(canned.body)
    assert canned.authorization == "Bearer test-key"
    assert parsed["model"] == "jev-1.13.0"
    assert parsed["disposition"] == "review"
    assert parsed["phone_home"] == 0.11


def test_a_key_hidden_from_json_does_not_reach_the_opener():
    quoted = 'pre"' + ("k" * 24)
    marked = "tail" + ("n" * 20) + "é"

    def opener(request, timeout):
        raise AssertionError("opener was called")

    for key in (quoted, marked):
        client = JevClient(key, opener=opener)
        try:
            client.judge({"note": key})
        except JudgeError as exc:
            assert "refusing" in str(exc)
            assert key not in str(exc)
        else:
            raise AssertionError("expected JudgeError")


def test_refuses_to_send_a_state_that_contains_the_key():
    client = JevClient("test-key", opener=canned)
    try:
        client.judge({"task": "test-key"})
    except JudgeError as exc:
        assert "refusing" in str(exc)
    else:
        raise AssertionError("expected JudgeError")
