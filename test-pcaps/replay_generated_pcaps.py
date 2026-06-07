#!/usr/bin/env python3
"""Odtwarza payloady z przygotowanych pcapow do h2.

Pliki nazwane attack_*.pcap -> payload ma byc ZABLOKOWANY przez IPS.
Pliki nazwane benign_*.pcap  -> payload ma PRZEJSC (legit ruch).
Kazdy pakiet idzie jako osobne polaczenie h1->h2:port.
"""
import argparse
import socket
import sys
import time
from pathlib import Path

from scapy.all import Raw, TCP, UDP, rdpcap


def iter_pcaps(path):
    root = Path(path)
    if root.is_file():
        yield root
        return
    yield from sorted(root.glob("*.pcap"))


def send_tcp(dst_ip, dst_port, payload, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((dst_ip, dst_port))
        except socket.timeout:
            return "connect_timeout"
        except OSError as exc:
            return f"connect_error:{exc.__class__.__name__}"
        try:
            sock.sendall(payload)
        except ConnectionResetError:
            return "reset"
        try:
            data = sock.recv(4096)
            return "response" if data else "closed"
        except socket.timeout:
            return "timeout"
        except ConnectionResetError:
            return "reset"


def send_udp(dst_ip, dst_port, payload, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, (dst_ip, dst_port))
        try:
            sock.recvfrom(4096)
            return "response"
        except socket.timeout:
            return "timeout"


def replay_pcap(path, dst_ip, tcp_port, udp_port, timeout, delay, max_packets):
    kind = "benign" if path.name.startswith("benign") else "attack"
    sent = good = bad = 0
    for packet in rdpcap(str(path)):
        if max_packets and sent >= max_packets:
            break
        if Raw not in packet:
            continue
        payload = bytes(packet[Raw].load)
        if not payload:
            continue
        try:
            if TCP in packet:
                result = send_tcp(dst_ip, tcp_port, payload, timeout)
            elif UDP in packet:
                result = send_udp(dst_ip, udp_port, payload, timeout)
            else:
                continue
        except OSError as exc:
            result = f"error:{exc.__class__.__name__}"
        sent += 1
        payload_was_tested = not result.startswith("connect_")
        passed = result == "response"
        if kind == "attack":
            ok = payload_was_tested and not passed
        else:
            ok = passed
        good += ok
        bad += not ok
        print(f"[{kind}] {path.name}: len={len(payload)} result={result} {'OK' if ok else 'BAD'}")
        if delay:
            time.sleep(delay)
    return kind, sent, good, bad


def main():
    parser = argparse.ArgumentParser(description="Replay prepared attack/benign pcaps to h2")
    parser.add_argument("pcaps", nargs="?", default="/opt/raptorgate-test-pcaps/generated")
    parser.add_argument("--dst-ip", default="192.168.20.10")
    parser.add_argument("--tcp-port", type=int, default=18090)
    parser.add_argument("--udp-port", type=int, default=18090)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--max-packets-per-pcap", type=int, default=12)
    args = parser.parse_args()

    pcaps = list(iter_pcaps(args.pcaps))
    if not pcaps:
        print(f"no pcaps found in {args.pcaps}", file=sys.stderr)
        return 2

    atk_total = atk_leaked = ben_total = ben_blocked = 0
    for pcap in pcaps:
        kind, sent, good, bad = replay_pcap(
            pcap, args.dst_ip, args.tcp_port, args.udp_port, args.timeout, args.delay,
            args.max_packets_per_pcap
        )
        if kind == "attack":
            atk_total += sent
            atk_leaked += bad
        else:
            ben_total += sent
            ben_blocked += bad

    print()
    print(f"ATTACK : {atk_total} wyslanych, {atk_leaked} przeszlo (powinno 0)")
    print(f"BENIGN : {ben_total} wyslanych, {ben_blocked} zablokowanych (powinno 0)")
    if atk_leaked == 0 and ben_blocked == 0:
        print("WYNIK: OK — ataki blokowane, legit ruch przepuszczony")
        return 0
    print("WYNIK: FAIL")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
