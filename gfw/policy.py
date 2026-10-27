"""Destination policy for agent egress.

The lists are the callback channels and metadata addresses documented in
docs/destinations.md. A name is denied when it is the suffix or a subdomain
of a suffix. `notaliyuncs.com` does not match `aliyuncs.com`.

Decision order:
1. Metadata and link-local addresses are denied, including when an operator
   tried to allowlist them.
2. Loopback is allowed.
3. An explicit host or suffix allow wins over a provider suffix.
4. Provider callback suffixes and operator extra suffixes are denied.
5. Other private addresses are denied unless allow_private is set.
6. A raw IP that was not allowlisted is denied.
7. Any other DNS name is review, which the proxy does not forward until a
   decider says allow.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from gfw.config import Config

# Object storage and cloud APIs. See docs/destinations.md for the vendor page
# behind each suffix. CDN scheduling names are intentionally absent.
HARD_DENY_SUFFIXES: tuple[str, ...] = (
    "aliyuncs.com",
    "myqcloud.com",
    "tencentcos.cn",
    "tencentcloudapi.com",
    "tencentyun.com",
    "bcebos.com",
    "baidubce.com",
    "myhuaweicloud.com",
    "myhuaweicloud.cn",
    "volces.com",
    "ivolces.com",
    "volcengineapi.com",
    "bytepluses.com",
    "ibytepluses.com",
    "bytepluses.com.cn",
    "ibytepluses.com.cn",
    "byteplusapi.com",
)

METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.tencentyun.com",
        "100.100.100.200",
        "100.96.0.96",
        "169.254.169.254",
    }
)

METADATA_IPS = frozenset(
    ipaddress.ip_address(item)
    for item in (
        "169.254.169.254",
        "100.100.100.200",
        "100.96.0.96",
        "fd00:ec2::254",
        "fd20:ce::254",
    )
)

LINK_LOCAL = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
)

PRIVATE = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


@dataclass(frozen=True)
class HostDecision:
    action: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"action": self.action, "reasons": list(self.reasons)}


def _ip(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _unwrap(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    """Return the IPv4 address embedded in a mapped, NAT64, or compatible form."""
    if isinstance(ip, ipaddress.IPv4Address):
        return ip
    mapped = ip.ipv4_mapped
    if mapped is not None:
        return mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(ip.packed[-4:])
    # IPv4-compatible ::/96. Leave :: and ::1 as IPv6 so loopback stays loopback.
    if ip.packed[:12] == bytes(12) and ip.packed[12:] not in (bytes(4), b"\x00\x00\x00\x01"):
        return ipaddress.IPv4Address(ip.packed[12:])
    return ip


def _strip_trailing_dots(text: str) -> str:
    # IDNA maps U+3002, U+FF0E, and U+FF61 onto an ASCII dot. Strip before and
    # after encoding so a trailing one cannot survive as "aliyuncs.com.".
    while text and text[-1] in ".。．｡":
        text = text[:-1]
    return text


def normalize_host(host: str) -> str:
    text = _strip_trailing_dots(host.strip().lower())
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    parsed = _ip(text)
    if parsed is not None:
        return str(parsed)
    try:
        encoded = _strip_trailing_dots(text.encode("idna").decode("ascii"))
    except UnicodeError as exc:
        raise ValueError("invalid host") from exc
    parsed = _ip(encoded)
    if parsed is not None:
        return str(parsed)
    return encoded


def matches_suffix(host: str, suffix: str) -> bool:
    suffix = suffix.lower().rstrip(".")
    return host == suffix or host.endswith("." + suffix)


def _is_metadata_ip(ip: ipaddress._BaseAddress) -> bool:
    ip = _unwrap(ip)
    if ip in METADATA_IPS:
        return True
    return any(ip in network for network in LINK_LOCAL)


def _is_loopback(ip: ipaddress._BaseAddress) -> bool:
    return bool(_unwrap(ip).is_loopback)


def _is_private(ip: ipaddress._BaseAddress) -> bool:
    ip = _unwrap(ip)
    return any(ip in network for network in PRIVATE)


def decide_host(
    host: str,
    port: int,
    config: Config,
    resolved_ips: list[str] | None = None,
) -> HostDecision:
    if port < 1 or port > 65535:
        return HostDecision("deny", ("invalid_port",))
    if not host or not host.strip():
        return HostDecision("deny", ("empty_host",))
    try:
        name = normalize_host(host)
    except ValueError:
        return HostDecision("deny", ("invalid_host",))

    ips: list[ipaddress._BaseAddress] = []
    own = _ip(name)
    if own is not None:
        ips.append(own)
    for item in resolved_ips or []:
        parsed = _ip(item)
        if parsed is not None:
            ips.append(parsed)

    unwrapped = [_unwrap(ip) for ip in ips]
    metadata_ip = any(ip in METADATA_IPS for ip in unwrapped)
    link_local = any(ip in network for ip in unwrapped for network in LINK_LOCAL)
    if metadata_ip or link_local or name in METADATA_HOSTS:
        if metadata_ip:
            reason = "metadata_ip"
        elif link_local:
            reason = "link_local"
        else:
            reason = "metadata_host"
        return HostDecision("deny", (reason,))

    if own is not None and _is_loopback(own):
        return HostDecision("allow", ("loopback",))
    if ips and all(_is_loopback(ip) for ip in ips):
        return HostDecision("allow", ("loopback",))

    if name in config.allow_hosts:
        return HostDecision("allow", ("allow_host",))
    for suffix in config.allow_suffixes:
        if matches_suffix(name, suffix):
            return HostDecision("allow", (f"allow_suffix:{suffix}",))

    for suffix in (*HARD_DENY_SUFFIXES, *sorted(config.extra_deny_suffixes)):
        if matches_suffix(name, suffix):
            return HostDecision("deny", (f"hard_deny:{suffix}",))

    if ips and any(_is_private(ip) for ip in ips) and not config.allow_private:
        return HostDecision("deny", ("private_ip",))

    if own is not None:
        return HostDecision("deny", ("ip_literal",))

    return HostDecision("review", ("dns_name_review",))
