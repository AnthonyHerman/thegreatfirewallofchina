import json
import socket
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gfw.config import default_config
from gfw.decide import Decision
from gfw.proxy import Gate, ProxyServer


class Pong(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"pong"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def config(tmp_path):
    return replace(default_config(), audit_path=str(tmp_path / "audit.jsonl"))


def serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def test_denied_host_is_not_dialed(tmp_path):
    def explode(*args, **kwargs):
        raise AssertionError("dialed")

    gate = Gate(config(tmp_path), connector=explode, resolver=explode)
    decision = gate.check("probe.oss-cn-beijing.aliyuncs.com", 443)
    assert decision.action == "block"
    assert any(reason.startswith("hard_deny:") for reason in decision.reasons)


def test_review_without_a_decider_does_not_dial(tmp_path):
    def explode(*args, **kwargs):
        raise AssertionError("dialed")

    gate = Gate(config(tmp_path), connector=explode, resolver=explode)
    decision = gate.check("example.com", 443)
    assert decision.action == "block"
    assert "review_without_decider" in decision.reasons


def test_decider_exception_blocks(tmp_path):
    def explode(*args, **kwargs):
        raise AssertionError("dialed")

    def decider(host, port):
        raise RuntimeError("judge down")

    gate = Gate(config(tmp_path), decider=decider, connector=explode, resolver=explode)
    decision = gate.check("example.com", 80)
    assert "decider_error" in decision.reasons


def test_proxy_forwards_loopback_and_rejects_connect(tmp_path):
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Pong)
    serve(origin)
    gate = Gate(config(tmp_path))
    proxy = ProxyServer(("127.0.0.1", 0), gate)
    serve(proxy)
    try:
        origin_port = origin.server_address[1]
        proxy_port = proxy.server_address[1]
        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
        request = (
            f"GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        assert b"pong" in data

        denied = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
        denied.sendall(
            b"CONNECT probe.oss-cn-beijing.aliyuncs.com:443 HTTP/1.1\r\n"
            b"Host: probe.oss-cn-beijing.aliyuncs.com:443\r\n\r\n"
        )
        body = b""
        while True:
            chunk = denied.recv(4096)
            if not chunk:
                break
            body += chunk
        denied.close()
        assert b"403" in body
        parsed = json.loads(body.split(b"\r\n\r\n", 1)[1])
        assert parsed["action"] == "block"
    finally:
        proxy.shutdown()
        origin.shutdown()
        proxy.server_close()
        origin.server_close()


def test_proxy_dials_the_checked_address_not_a_second_lookup(tmp_path):
    calls = {"n": 0}
    seen = []
    held = []

    def resolver(host, port):
        calls["n"] += 1
        if calls["n"] == 1:
            return ["127.0.0.1"]
        return ["169.254.169.254"]

    def connector(address, timeout):
        seen.append(address)
        local, remote = socket.socketpair()
        held.append(remote)
        return local

    cfg = replace(
        default_config(),
        allow_hosts=frozenset({"example.com", "localhost", "127.0.0.1", "::1"}),
        audit_path=str(tmp_path / "audit.jsonl"),
    )
    proxy = ProxyServer(("127.0.0.1", 0), Gate(cfg, resolver=resolver, connector=connector))
    serve(proxy)
    try:
        port = proxy.server_address[1]
        sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        sock.sendall(
            b"GET http://example.com:9/secret HTTP/1.1\r\n"
            b"Host: example.com:9\r\n"
            b"Connection: close\r\n\r\n"
        )
        for _ in range(50):
            if held:
                break
            sock.settimeout(0.05)
            try:
                sock.recv(1)
            except TimeoutError:
                pass
        assert seen == [("127.0.0.1", 9)]
        assert calls["n"] == 1
        upstream = held[0]
        upstream.settimeout(2)
        sent = upstream.recv(4096)
        upstream.close()
        assert b"Host: example.com:9" in sent
        assert b"/secret" in sent
    finally:
        proxy.shutdown()
        proxy.server_close()
        sock.close()


def test_decider_allow_still_checks_resolution(tmp_path):
    def decider(host, port):
        return Decision("allow", ("jev:allow",), (), (), None)

    def resolver(host, port):
        return ["169.254.169.254"]

    def explode(*args, **kwargs):
        raise AssertionError("dialed")

    gate = Gate(config(tmp_path), decider=decider, connector=explode, resolver=resolver)
    decision = gate.check("example.com", 443)
    assert decision.action == "block"
    assert "metadata_ip" in decision.reasons
