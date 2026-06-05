#!/usr/bin/env python3
"""Pobiera prawdziwe pcapy, wypakowuje i wycina z nich pakiety atakow.

Z kazdego zrodla zostawia TYLKO pakiety IPv4 TCP/UDP, ktorych payload zawiera
ktoras sygnature IPS (z config-import-in-frontend.json). Caly szum (handshake,
ACK-i, tresc odpowiedzi serwera, segmenty continuation) jest wyrzucany.
Zostawione pakiety sa przepisywane na trase h1 (192.168.10.10) ->
h2 (192.168.20.10) port 18090 z przeliczeniem sum kontrolnych.

Dzieki temu replay = jedno krotkie polaczenie na pakiet-atak, kazde realnie
niesie sygnature. Wynik w test-pcaps/generated/ (gitignore).
"""
import argparse
import gzip
import json
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


H1_IP = "192.168.10.10"
H2_IP = "192.168.20.10"
DST_PORT = 18090
MAX_PAYLOAD = 8192
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) RaptorGate-test/1.0"

SOURCES = [
    {"name": "01-cve-2024-4577-probe", "kind": "zip", "password": "infected_20240611",
     "url": "https://www.malware-traffic-analysis.net/2024/06/11/2024-06-11-CVE-2024-4577-probe.pcap.zip"},
    {"name": "02-phishing-webmail", "kind": "zip", "password": "infected_20240829",
     "url": "https://www.malware-traffic-analysis.net/2024/08/29/2024-08-29-phishing-website-traffic.pcap.zip"},
    {"name": "03-qakbot", "kind": "zip", "password": "infected_20230227",
     "url": "https://www.malware-traffic-analysis.net/2023/02/27/2023-02-27-Qakbot-infection-traffic.pcap.zip"},
    {"name": "04-dns-remoteshell", "kind": "plain", "password": None,
     "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns-remoteshell.pcap"},
    {"name": "05-slammer", "kind": "plain", "password": None,
     "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/slammer.pcap"},
    {"name": "06-slashdot", "kind": "plain", "password": None,
     "url": "https://s3.amazonaws.com/tcpreplay-pcap-files/test.pcap"},
    {"name": "07-smallflows", "kind": "plain", "password": None,
     "url": "https://s3.amazonaws.com/tcpreplay-pcap-files/smallFlows.pcap"},
    {"name": "08-protos-bugbear", "kind": "gz", "password": None,
     "url": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/c05-http-reply-r1.pcap.gz"},
]


# ---------- sygnatury ----------

def load_patterns(config_path):
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    signatures = config.get("signatures")
    if signatures is None:
        signatures = (
            config.get("payloadJson", {})
            .get("bundle", {})
            .get("ips_config", {})
            .get("signatures", [])
        )
    patterns = []
    for sig in signatures:
        if sig.get("isActive", sig.get("enabled", True)) is not True:
            continue
        enc = sig.get("patternEncoding", "")
        pat = sig["pattern"]
        data = bytes.fromhex(pat) if enc in {"IPS_PATTERN_ENCODING_HEX", "hex"} else pat.encode()
        if data:
            patterns.append(data)
    return patterns


def payload_matches(payload, patterns):
    return any(p in payload for p in patterns)


HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ")


def is_http_request(payload):
    return any(payload.startswith(m) for m in HTTP_METHODS)


# ---------- download / extract ----------

def download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp, dest.open("wb") as fh:
        shutil.copyfileobj(resp, fh)


def find_capture(directory):
    for child in sorted(directory.rglob("*")):
        if child.suffix.lower() in {".pcap", ".cap", ".pcapng"}:
            return child
    return None


def extract(src, kind, password, work_dir):
    if kind == "plain":
        return src
    if kind == "gz":
        out = work_dir / (src.stem if src.suffix == ".gz" else src.name + ".pcap")
        with gzip.open(src, "rb") as fin, out.open("wb") as fout:
            shutil.copyfileobj(fin, fout)
        return out
    if kind == "zip":
        out_dir = work_dir / (src.stem + "-x")
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd = ["unzip", "-o"]
        if password:
            cmd += ["-P", password]
        cmd += [str(src), "-d", str(out_dir)]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        found = find_capture(out_dir)
        if not found:
            raise RuntimeError(f"no capture inside {src}")
        return found
    raise ValueError(f"unknown kind {kind}")


# ---------- pcap parse / rewrite ----------

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse_eth_ipv4(frame):
    """Zwraca (offset_ip, ihl, proto, l4_offset, payload) albo None."""
    if len(frame) < 14:
        return None
    eth_type = int.from_bytes(frame[12:14], "big")
    off = 14
    if eth_type == 0x8100 and len(frame) >= 18:
        eth_type = int.from_bytes(frame[16:18], "big")
        off = 18
    if eth_type != 0x0800:
        return None
    ip = frame[off:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    if proto == 6 and len(ip) >= ihl + 20:
        doff = ((ip[ihl + 12] >> 4) & 0xF) * 4
        payload = ip[ihl + doff:]
    elif proto == 17 and len(ip) >= ihl + 8:
        payload = ip[ihl + 8:]
    else:
        return None
    return off, ihl, proto, payload


def rewrite_to_test(frame, off, ihl, proto):
    """Przepisuje IPv4 TCP/UDP na h1->h2:DST_PORT, poprawia sumy kontrolne."""
    ip = bytearray(frame[off:])
    ip[12:16] = socket.inet_aton(H1_IP)
    ip[16:20] = socket.inet_aton(H2_IP)
    src_raw = bytes(ip[12:16])
    dst_raw = bytes(ip[16:20])
    l4 = ip[ihl:]
    if proto == 6:
        l4[2:4] = struct.pack("!H", DST_PORT)
        l4[16:18] = b"\x00\x00"
        pseudo = struct.pack("!4s4sBBH", src_raw, dst_raw, 0, proto, len(l4))
        l4[16:18] = struct.pack("!H", checksum(pseudo + bytes(l4)))
    else:
        l4[2:4] = struct.pack("!H", DST_PORT)
        l4[6:8] = b"\x00\x00"
        pseudo = struct.pack("!4s4sBBH", src_raw, dst_raw, 0, proto, len(l4))
        cks = checksum(pseudo + bytes(l4))
        l4[6:8] = struct.pack("!H", cks if cks else 0xFFFF)
    ip[ihl:] = l4
    ip[10:12] = b"\x00\x00"
    ip[10:12] = struct.pack("!H", checksum(bytes(ip[:ihl])))
    return frame[:off] + bytes(ip)


def carve_pcap(in_path, out_path, keep_fn, limit=0, seen=None):
    """Zostawia pakiety dla ktorych keep_fn(payload)==True, przepisane na h1->h2.

    limit>0 ogranicza liczbe; seen (set) deduplikuje po payload[:64]. Zwraca liczbe.
    """
    data = in_path.read_bytes()
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        return 0  # pcapng/nieznany — pomijamy

    network = struct.unpack(endian + "I", data[20:24])[0]
    if network != 1:
        return 0  # tylko Ethernet

    out = bytearray(data[:24])
    off = 24
    kept = 0
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        frame = data[off:off + incl]
        off += incl
        if len(frame) < incl:
            break
        if limit and kept >= limit:
            break
        parsed = parse_eth_ipv4(frame)
        if not parsed:
            continue
        ip_off, ihl, proto, payload = parsed
        if not payload or not keep_fn(payload):
            continue
        if seen is not None:
            key = bytes(payload[:64])
            if key in seen:
                continue
            seen.add(key)
        new_frame = rewrite_to_test(frame, ip_off, ihl, proto)
        out += struct.pack(endian + "IIII", ts_sec, ts_usec, len(new_frame), len(new_frame))
        out += new_frame
        kept += 1

    if kept:
        out_path.write_bytes(out)
    return kept


def main():
    parser = argparse.ArgumentParser(description="Download + carve real attack packets into h1->h2 test pcaps")
    parser.add_argument("--config", default="test-pcaps/config-import-in-frontend.json")
    parser.add_argument("--out-dir", default="test-pcaps/generated")
    parser.add_argument("--benign-per-source", type=int, default=3,
                        help="ile czystych requestow HTTP (bez sygnatury) wyciac na zrodlo")
    parser.add_argument("--keep-raw", action="store_true")
    args = parser.parse_args()

    patterns = load_patterns(args.config)
    if not patterns:
        print("brak aktywnych sygnatur w configu", file=sys.stderr)
        return 1
    print(f"[*] zaladowano {len(patterns)} sygnatur do dopasowania")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("*.pcap"):
        old.unlink()

    raw_dir = out_dir / "raw"
    raw_dir.mkdir(exist_ok=True)

    def is_attack(payload):
        return payload_matches(payload, patterns)

    def is_benign_request(payload):
        return is_http_request(payload) and not payload_matches(payload, patterns)

    attack_pkts = 0
    benign_pkts = 0
    benign_seen = set()
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for source in SOURCES:
            name = source["name"]
            raw_path = raw_dir / source["url"].rsplit("/", 1)[-1]
            try:
                print(f"[*] {name}: pobieranie")
                download(source["url"], raw_path)
                capture = extract(raw_path, source["kind"], source["password"], work)

                atk = carve_pcap(capture, out_dir / f"attack_{name}.pcap", is_attack)
                if atk:
                    attack_pkts += atk
                    print(f"    -> attack_{name}.pcap: {atk} pakietow-atak")

                ben = carve_pcap(capture, out_dir / f"benign_{name}.pcap",
                                 is_benign_request, limit=args.benign_per_source, seen=benign_seen)
                if ben:
                    benign_pkts += ben
                    print(f"    -> benign_{name}.pcap: {ben} czystych requestow")

                if not atk and not ben:
                    print(f"    -> {name}: nic do wyciecia, pominieto", file=sys.stderr)
            except Exception as exc:  # noqa: BLE001
                print(f"    ! {name}: {exc.__class__.__name__}: {exc}", file=sys.stderr)

    if not args.keep_raw:
        shutil.rmtree(raw_dir, ignore_errors=True)

    print(f"\nGotowe w {out_dir}: {attack_pkts} pakietow-atak (maja byc blokowane), "
          f"{benign_pkts} czystych requestow (maja przejsc)")
    return 0 if (attack_pkts or benign_pkts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
