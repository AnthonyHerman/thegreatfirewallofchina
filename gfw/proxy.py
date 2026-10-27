"""Local HTTP and CONNECT proxy.

Only an allow decision is dialed. A deny is rejected without a connection.
A review destination is rejected unless the decider returns allow, and that
allow is checked again after DNS resolution. A decider exception is a block.
"""

from __future__ import annotations

import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from gfw.audit import write_audit
from gfw.config import Config
from gfw.decide import Decision
from gfw.policy import decide_host


class Gate:
    def __init__(self, config: Config, decider=None, connector=None, resolver=None):
        self.config = config
        self.decider = decider
        self.connector = connector or socket.create_connection
        self.resolver = resolver or _resolve

    def check(self, host: str, port: int) -> Decision:
        host_decision = decide_host(host, port, self.config)
        if host_decision.action == "deny":
            decision = _blocked(host_decision.reasons)
        elif host_decision.action == "review":
            decision = self._review(host, port, host_decision.reasons)
        else:
            decision = self._confirm(host, port, host_decision.reasons)
        try:
            write_audit(
                self.config.audit_path,
                {"kind": "egress", "host": host, "port": port, "decision": decision.to_dict()},
            )
        except OSError:
            pass
        return decision

    def _review(self, host: str, port: int, reasons: tuple[str, ...]) -> Decision:
        if self.decider is None:
            return _blocked(reasons + ("review_without_decider",))
        try:
            decided = self.decider(host, port)
        except Exception:
            return _blocked(reasons + ("decider_error",))
        if not isinstance(decided, Decision):
            return _blocked(reasons + ("decider_error",))
        if decided.action != "allow":
            # The proxy forwards only an allow. Review stays on the operator's side.
            return Decision(
                "block",
                reasons + decided.reasons + (f"decider:{decided.action}",),
                decided.policy,
                decided.signals,
                decided.judge,
            )
        return self._confirm(host, port, reasons + decided.reasons)

    def _confirm(self, host: str, port: int, reasons: tuple[str, ...]) -> Decision:
        try:
            ips = self.resolver(host, port)
        except OSError:
            return _blocked(reasons + ("dns_failed",))
        again = decide_host(host, port, self.config, resolved_ips=ips)
        if again.action != "allow":
            return _blocked(reasons + again.reasons + ("resolved_destination",))
        return Decision("allow", reasons + again.reasons, (), (), None)


def _blocked(reasons: tuple[str, ...]) -> Decision:
    return Decision("block", reasons, (), (), None)


def _resolve(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({item[4][0] for item in infos})


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        return

    def do_CONNECT(self) -> None:
        host, _, port_text = self.path.partition(":")
        try:
            port = int(port_text or "443")
        except ValueError:
            port = 0
        decision = self.server.gate.check(host, port)
        if decision.action != "allow":
            self._reject(decision)
            return
        try:
            remote = self.server.gate.connector((host, port), 10)
        except OSError:
            self._reject(Decision("block", ("dial_failed",), (), (), None))
            return
        try:
            self.send_response(200, "Connection Established")
            self.end_headers()
            self._splice(remote)
        finally:
            remote.close()

    def do_GET(self) -> None:
        self._forward()

    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_HEAD = do_GET
    do_PATCH = do_GET
    do_OPTIONS = do_GET

    def _forward(self) -> None:
        host, port, path = _target(self.path, self.headers.get("Host", ""))
        decision = self.server.gate.check(host, port)
        if decision.action != "allow":
            self._reject(decision)
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        raw = _origin_request(self.command, path, self.headers, body)
        try:
            remote = self.server.gate.connector((host, port), 10)
        except OSError:
            self._reject(Decision("block", ("dial_failed",), (), (), None))
            return
        try:
            remote.sendall(raw)
            while True:
                chunk = remote.recv(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
        finally:
            remote.close()

    def _reject(self, decision: Decision) -> None:
        body = json.dumps(decision.to_dict()).encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _splice(self, remote: socket.socket) -> None:
        sockets = [self.connection, remote]
        remote.settimeout(10)
        self.connection.settimeout(10)
        while True:
            try:
                ready = _select(sockets)
            except OSError:
                break
            if not ready:
                break
            for sock in ready:
                other = remote if sock is self.connection else self.connection
                try:
                    chunk = sock.recv(65536)
                except OSError:
                    return
                if not chunk:
                    return
                try:
                    other.sendall(chunk)
                except OSError:
                    return


def _select(sockets: list[socket.socket]) -> list[socket.socket]:
    import select

    readable, _, _ = select.select(sockets, [], [], 10)
    return list(readable)


def _target(path: str, host_header: str) -> tuple[str, int, str]:
    if path.startswith("http://") or path.startswith("https://"):
        parts = urlsplit(path)
        default = 443 if parts.scheme == "https" else 80
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        return parts.hostname or "", parts.port or default, target
    host, _, port_text = host_header.partition(":")
    try:
        port = int(port_text) if port_text else 80
    except ValueError:
        port = 0
    return host, port, path or "/"


def _origin_request(method: str, path: str, headers, body: bytes) -> bytes:
    lines = [f"{method} {path} HTTP/1.1"]
    for key, value in headers.items():
        if key.lower() in {"proxy-connection", "proxy-authorization"}:
            continue
        lines.append(f"{key}: {value}")
    if not any(line.lower().startswith("connection:") for line in lines):
        lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + body


class ProxyServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], gate: Gate):
        super().__init__(address, ProxyHandler)
        self.gate = gate
