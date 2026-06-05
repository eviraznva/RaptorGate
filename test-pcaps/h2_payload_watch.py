#!/usr/bin/env python3
import argparse
import json
import socket
import socketserver
import time
from pathlib import Path


class WatchState:
    def __init__(self, patterns, log_path):
        self.patterns = patterns
        self.log_path = log_path
        self.violations = []

    def record(self, peer, payload, matched):
        item = {
            "peer": f"{peer[0]}:{peer[1]}",
            "signature": matched["name"],
            "payloadLength": len(payload),
            "timestamp": time.time(),
        }
        self.violations.append(item)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(item, sort_keys=True))
            fh.write("\n")


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(1.0)
        try:
            payload = self.request.recv(65535)
        except socket.timeout:
            return
        for pattern in self.server.state.patterns:
            if pattern["bytes"] in payload:
                self.server.state.record(self.client_address, payload, pattern)
        try:
            self.request.sendall(b"ok\n")
        except OSError:
            pass


class WatchServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, address, handler, state):
        super().__init__(address, handler)
        self.state = state


def load_patterns(config_path):
    with Path(config_path).open("r", encoding="utf-8") as fh:
        config = json.load(fh)
    signatures = config.get("signatures")
    if signatures is None:
        signatures = (
            config.get("payloadJson", {})
            .get("bundle", {})
            .get("ips_config", {})
            .get("signatures", [])
        )
    patterns = []
    for signature in signatures:
        if signature.get("isActive", signature.get("enabled", True)) is not True:
            continue
        encoding = signature.get("patternEncoding", "")
        pattern = signature["pattern"]
        data = bytes.fromhex(pattern) if encoding in {"IPS_PATTERN_ENCODING_HEX", "hex"} else pattern.encode()
        patterns.append({"id": signature["id"], "name": signature["name"], "bytes": data})
    return patterns


def main():
    parser = argparse.ArgumentParser(description="Watch h2 for IPS payloads that should be blocked")
    parser.add_argument("--config", default="/opt/raptorgate-test-pcaps/config-import-in-frontend.json")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18090)
    parser.add_argument("--seconds", type=float, default=60.0)
    parser.add_argument("--log", default="/tmp/raptorgate-ips-watch.log")
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.unlink(missing_ok=True)
    state = WatchState(load_patterns(args.config), log_path)

    with WatchServer((args.listen, args.port), TcpHandler, state) as server:
        server.timeout = 0.25
        server.socket.settimeout(0.25)
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            server.handle_request()

    if state.violations:
        print(f"FAILED: observed {len(state.violations)} forbidden payload(s); see {log_path}")
        return 1
    print("OK: no forbidden payload observed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
