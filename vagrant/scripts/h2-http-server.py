#!/usr/bin/env python3
# Prosty endpoint testowy na h2 dla Issue 1 (kryterium: h2 ma dzialajacy endpoint).
# Ochrona to zadanie firewalla (Issue 5/6), ten serwis tylko odpowiada.
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

LISTEN_ADDR = ("0.0.0.0", 8080)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self._send(200, "text/plain; charset=utf-8", b"RaptorGate h2-http service\n")
        elif self.path == "/api/ping":
            self._send(200, "application/json", json.dumps({"status": "ok"}).encode() + b"\n")
        elif self.path == "/api/whoami":
            body = json.dumps({"service": "h2-http", "resource": "protected"}).encode() + b"\n"
            self._send(200, "application/json", body)
        else:
            self._send(404, "text/plain; charset=utf-8", b"not found\n")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    HTTPServer(LISTEN_ADDR, Handler).serve_forever()
