"""Command line for the destination gate, the trace judge, and the proxy."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from gfw import __version__
from gfw.analyst import Analyst
from gfw.audit import write_audit
from gfw.config import load_config
from gfw.decide import Decision, evaluate
from gfw.judge import JevClient
from gfw.policy import decide_host
from gfw.proxy import Gate, ProxyServer
from gfw.scan import scan_tree
from gfw.trace import load_trace

FIXTURES = Path(__file__).resolve().parent / "fixtures"
EXIT = {"allow": 0, "review": 2, "block": 3}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gfw")
    parser.add_argument("--version", action="version", version=f"gfw {__version__}")
    parser.add_argument("--config", help="JSON file with allow_hosts and thresholds")
    sub = parser.add_subparsers(dest="command", required=True)

    egress = sub.add_parser("egress", help="Decide one destination")
    egress.add_argument("host")
    egress.add_argument("--port", type=int, default=443)
    egress.add_argument("--offline", action="store_true")
    egress.set_defaults(func=cmd_egress)

    judge = sub.add_parser("judge", help="Judge one agent trace")
    judge.add_argument("trace", type=Path)
    judge.add_argument("--offline", action="store_true")
    judge.set_defaults(func=cmd_judge)

    proxy = sub.add_parser("proxy", help="Run the egress proxy")
    proxy.add_argument("--listen", default="127.0.0.1:8080")
    proxy.add_argument("--offline", action="store_true", help="Block review destinations instead of asking JEV")
    proxy.set_defaults(func=cmd_proxy)

    demo = sub.add_parser("demo", help="Judge the shipped fixtures")
    demo.add_argument("--offline", action="store_true")
    demo.set_defaults(func=cmd_demo)

    scan = sub.add_parser("scan", help="Fail if secret-shaped strings are in a tree")
    scan.add_argument("path", nargs="?", default=".")
    scan.set_defaults(func=cmd_scan)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 1
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_egress(args) -> int:
    config = load_config(args.config)
    host_decision = decide_host(args.host, args.port, config)
    if host_decision.action == "deny":
        decision = Decision("block", host_decision.reasons, (), (), None)
    elif host_decision.action == "allow":
        decision = Decision("allow", host_decision.reasons, (), (), None)
    elif args.offline:
        decision = Decision("review", host_decision.reasons, (), (), None)
    else:
        decision = _judge_destination(config, args.host, args.port)
    _audit(config, {"kind": "egress", "host": args.host, "port": args.port, "decision": decision.to_dict()})
    return _emit(decision)


def cmd_judge(args) -> int:
    config = load_config(args.config)
    trace = load_trace(args.trace)
    decision = _judge_trace(config, trace, offline=args.offline, explain=config.analyst and not args.offline)
    _audit(config, {"kind": "trace", "id": trace.get("id"), "decision": decision.to_dict()})
    return _emit(decision)


def cmd_demo(args) -> int:
    config = load_config(args.config)
    worst = "allow"
    blocked: tuple[dict, Decision] | None = None
    for path in sorted(FIXTURES.glob("*.json")):
        trace = load_trace(path)
        decision = _judge_trace(config, trace, offline=args.offline, explain=False)
        print(f"# {path.name}")
        _emit(decision)
        if EXIT[decision.action] > EXIT[worst]:
            worst = decision.action
        if decision.action == "block" and blocked is None:
            blocked = (trace, decision)
    if blocked and config.analyst and not args.offline:
        trace, decision = blocked
        explained = _explain(config, trace, decision)
        print("# analyst")
        print(json.dumps(explained, indent=2))
    return EXIT[worst]


def cmd_proxy(args) -> int:
    config = load_config(args.config)
    host, port = _listen(args.listen)
    decider = None if args.offline else lambda destination, dest_port: _judge_destination(config, destination, dest_port)
    server = ProxyServer((host, port), Gate(config, decider=decider))
    bound = server.server_address
    print(f"listening on {bound[0]}:{bound[1]}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


def cmd_scan(args) -> int:
    findings = scan_tree(Path(args.path))
    if not findings:
        print("scan clean")
        return 0
    for item in findings:
        print(f"{item['path']}:{item['line']}: {item['match']}")
    return 1


def _judge_destination(config, host: str, port: int) -> Decision:
    trace = {
        "id": "egress",
        "task": "egress check",
        "reasoning": "",
        "actions": [{"kind": "connect", "host": host, "port": port}],
    }
    return _judge_trace(config, trace, offline=False, explain=False)


def _judge_trace(config, trace: dict, offline: bool, explain: bool) -> Decision:
    judge = None if offline else _jev(config)
    decision = evaluate(trace, config, judge)
    if explain and decision.action != "allow":
        analyst = _explain(config, trace, decision)
        decision = Decision(
            decision.action,
            decision.reasons,
            decision.policy,
            decision.signals,
            decision.judge,
            analyst,
        )
    return decision


def _jev(config) -> JevClient:
    return JevClient(os.environ.get("JEV_API_KEY", ""), model=config.jev_model)


def _explain(config, trace: dict, decision: Decision) -> dict:
    analyst = Analyst(
        api_key=os.environ.get("ABLITERATION_API_KEY", ""),
        model=config.analyst_model,
        min_balance=config.analyst_min_balance,
        max_tokens=config.analyst_max_tokens,
    )
    return analyst.explain(trace, decision)


def _listen(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not host:
        raise ValueError("listen address must look like 127.0.0.1:8080")
    return host, int(port)


def _audit(config, record: dict) -> None:
    try:
        write_audit(config.audit_path, record)
    except OSError:
        return


def _emit(decision: Decision) -> int:
    print(json.dumps(decision.to_dict(), indent=2))
    return EXIT[decision.action]
