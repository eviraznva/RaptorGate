#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import random
import socket
import string
import subprocess
import time


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 587, 993, 995, 1433, 3306, 3389, 4444, 8080]


def ensure_route(target: str, gateway: str, iface: str) -> None:
    if os.geteuid() != 0:
        return
    subnet = ".".join(target.split(".")[:3]) + ".0/24"
    subprocess.run(
        ["ip", "route", "replace", subnet, "via", gateway, "dev", iface],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def random_token(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def tcp_probe(target: str, port: int, timeout: float) -> None:
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            payload = (
                f"GET /../../../../etc/passwd?cmd={random_token()} HTTP/1.1\r\n"
                f"Host: {random_token(12)}.invalid\r\n"
                "User-Agent: sqlmap/1.7 RaptorGate-ML-Probe\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            sock.sendall(payload)
    except OSError:
        pass


def udp_probe(target: str, port: int) -> None:
    payload = os.urandom(random.randint(64, 512))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, (target, port))
    except OSError:
        pass


def run(args: argparse.Namespace) -> None:
    ensure_route(args.target, args.gateway, args.interface)
    ports = args.ports or DEFAULT_PORTS
    deadline = time.monotonic() + args.duration
    interval = 1.0 / max(args.rate, 1)
    sent = 0

    while time.monotonic() < deadline:
        port = random.choice(ports)
        if args.mode in ("mixed", "tcp"):
            tcp_probe(args.target, port, args.timeout)
            sent += 1
        if args.mode in ("mixed", "udp"):
            udp_probe(args.target, port)
            sent += 1
        time.sleep(interval)

    print(f"sent_probe_attempts={sent} target={args.target} duration={args.duration}s")


def parse_ports(raw: str | None) -> list[int] | None:
    if raw is None:
        return None
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return [port for port in ports if 0 < port < 65536]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="192.168.10.10")
    parser.add_argument("--gateway", default="192.168.20.254")
    parser.add_argument("--interface", default="eth1")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--rate", type=int, default=150)
    parser.add_argument("--timeout", type=float, default=0.08)
    parser.add_argument("--mode", choices=("mixed", "tcp", "udp"), default="mixed")
    parser.add_argument("--ports", type=parse_ports)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
