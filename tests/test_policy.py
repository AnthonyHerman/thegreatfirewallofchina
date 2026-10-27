from gfw.config import default_config
from gfw.policy import decide_host


def test_oss_beijing_is_denied():
    decision = decide_host("probe-bucket.oss-cn-beijing.aliyuncs.com", 443, default_config())
    assert decision.action == "deny"
    assert decision.reasons == ("hard_deny:aliyuncs.com",)


def test_suffix_is_not_a_substring():
    config = default_config()
    assert decide_host("notaliyuncs.com", 443, config).action == "review"
    assert decide_host("aliyuncs.com.evil.example", 443, config).action == "review"


def test_allowlist_beats_provider_suffix_and_not_metadata():
    config = default_config().with_overrides(
        {"allow_hosts": ["dashscope.aliyuncs.com", "169.254.169.254", "127.0.0.1"]}
    )
    assert decide_host("dashscope.aliyuncs.com", 443, config).action == "allow"
    assert decide_host("oss-cn-beijing.aliyuncs.com", 443, config).action == "deny"
    metadata = decide_host("169.254.169.254", 80, config)
    assert metadata.action == "deny"
    assert metadata.reasons == ("metadata_ip",)


def test_metadata_addresses():
    config = default_config()
    assert decide_host("100.100.100.200", 80, config).reasons == ("metadata_ip",)
    assert decide_host("100.96.0.96", 80, config).reasons == ("metadata_ip",)
    assert decide_host("fd00:ec2::254", 80, config).reasons == ("metadata_ip",)
    assert decide_host("fd20:ce::254", 80, config).reasons == ("metadata_ip",)
    assert decide_host("metadata.google.internal", 80, config).reasons == ("metadata_host",)
    assert decide_host("metadata.tencentyun.com", 80, config).reasons == ("metadata_host",)
    assert decide_host("169.254.1.1", 80, config).reasons == ("link_local",)


def test_loopback_private_and_raw_ip():
    config = default_config()
    assert decide_host("127.0.0.1", 8000, config).action == "allow"
    assert decide_host("::1", 8000, config).action == "allow"
    assert decide_host("localhost", 443, config).action == "allow"
    assert decide_host("10.1.1.1", 443, config).reasons == ("private_ip",)
    assert decide_host("192.168.1.5", 443, config).reasons == ("private_ip",)
    assert decide_host("8.8.8.8", 443, config).reasons == ("ip_literal",)
    assert decide_host("example.com", 443, config).action == "review"


def test_ipv4_mapped_metadata_stays_denied():
    config = default_config().with_overrides({"allow_hosts": ["example.com", "::ffff:169.254.169.254"]})
    mapped = "::ffff:169.254.169.254"
    direct = decide_host(mapped, 80, config)
    assert direct.action == "deny"
    rebound = decide_host("example.com", 443, config, resolved_ips=[mapped])
    assert rebound.action == "deny"
    assert rebound.reasons == ("metadata_ip",)


def test_trailing_fullwidth_dots_stay_denied():
    config = default_config().with_overrides(
        {"allow_hosts": ["probe.oss-cn-beijing.aliyuncs.com.", "metadata.google.internal.", "169.254.169.254."]}
    )
    samples = [
        "probe.oss-cn-beijing.aliyuncs.com。",
        "probe.oss-cn-beijing.aliyuncs.com．",
        "probe.oss-cn-beijing.aliyuncs.com｡",
        "metadata.google.internal。",
        "169.254.169.254。",
        "169.254.169.254．",
    ]
    for host in samples:
        decision = decide_host(host, 443, config)
        assert decision.action == "deny", host


def test_nat64_and_compatible_metadata_stay_denied():
    config = default_config().with_overrides({"allow_hosts": ["example.com"]})
    for address in ("64:ff9b::a9fe:a9fe", "64:ff9b::6464:64c8", "::a9fe:a9fe"):
        assert decide_host(address, 80, config).action == "deny"
        rebound = decide_host("example.com", 443, config, resolved_ips=[address])
        assert rebound.action == "deny", address
        assert rebound.reasons == ("metadata_ip",)
    assert decide_host("::1", 80, default_config()).action == "allow"


def test_resolved_metadata_is_denied_for_an_ordinary_name():
    decision = decide_host(
        "example.com",
        443,
        default_config(),
        resolved_ips=["169.254.169.254"],
    )
    assert decision.action == "deny"
    assert decision.reasons == ("metadata_ip",)
