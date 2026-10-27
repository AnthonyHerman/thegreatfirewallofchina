from gfw.redact import redact


def test_redacts_nested_secrets_without_a_network_call():
    planted = "ak_" + ("a" * 20)
    bearer = "Bearer " + ("b" * 24)
    value = {"headers": {"Authorization": bearer}, "note": planted, "n": 1}
    cleaned = redact(value)
    assert planted not in str(cleaned)
    assert "bbbb" not in str(cleaned)
    assert cleaned["n"] == 1
    assert cleaned["note"] == "[redacted]"
