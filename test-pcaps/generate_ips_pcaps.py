#!/usr/bin/env python3
import argparse
import json
import re
import socket
import struct
import time
from pathlib import Path


DEFAULT_SRC_IP = "192.168.10.10"
DEFAULT_DST_IP = "192.168.20.10"
DEFAULT_DST_PORT = 18090


def slugify(value):
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "signature"


def is_enabled(signature):
    return signature.get("isActive", signature.get("enabled", True)) is True


def pattern_bytes(signature):
    encoding = signature.get("patternEncoding", "")
    pattern = signature["pattern"]
    if encoding in {"IPS_PATTERN_ENCODING_HEX", "hex"}:
        return bytes.fromhex(pattern)
    return pattern.encode()


def load_signatures(config_path):
    with config_path.open("r", encoding="utf-8") as fh:
        config = json.load(fh)
    signatures = config.get("signatures")
    if signatures is None:
        signatures = (
            config.get("payloadJson", {})
            .get("bundle", {})
            .get("ips_config", {})
            .get("signatures", [])
        )
    return [signature for signature in signatures if is_enabled(signature)]


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_packet(src_ip, dst_ip, src_port, dst_port, payload):
    src_raw = socket.inet_aton(src_ip)
    dst_raw = socket.inet_aton(dst_ip)
    tcp_len = 20 + len(payload)
    total_len = 20 + tcp_len

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        src_raw,
        dst_raw,
    )
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        1,
        1,
        5 << 4,
        0x18,
        64240,
        0,
        0,
    )
    pseudo_header = struct.pack("!4s4sBBH", src_raw, dst_raw, 0, socket.IPPROTO_TCP, tcp_len)
    tcp_header = tcp_header[:16] + struct.pack("!H", checksum(pseudo_header + tcp_header + payload)) + tcp_header[18:]

    ethernet = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return ethernet + ip_header + tcp_header + payload


def write_single_packet_pcap(path, packet):
    now = time.time()
    sec = int(now)
    usec = int((now - sec) * 1_000_000)
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_header = struct.pack("<IIII", sec, usec, len(packet), len(packet))
    path.write_bytes(global_header + packet_header + packet)


def write_pcap(signature, index, out_dir, src_ip, dst_ip, default_dst_port):
    payload = pattern_bytes(signature)
    dst_ports = signature.get("dstPorts") or [default_dst_port]
    dst_port = int(dst_ports[0])
    src_port = 40000 + index
    name = f"{index:02d}-{slugify(signature['name'])}.pcap"
    path = out_dir / name
    write_single_packet_pcap(path, tcp_packet(src_ip, dst_ip, src_port, dst_port, payload))
    return path, len(payload)


def main():
    parser = argparse.ArgumentParser(description="Generate minimal IPS test PCAPs from backend IPS config")
    parser.add_argument("--config", default="test-pcaps/config-import-in-frontend.json")
    parser.add_argument("--out-dir", default="test-pcaps/generated")
    parser.add_argument("--src-ip", default=DEFAULT_SRC_IP)
    parser.add_argument("--dst-ip", default=DEFAULT_DST_IP)
    parser.add_argument("--dst-port", type=int, default=DEFAULT_DST_PORT)
    args = parser.parse_args()

    config_path = Path(args.config)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for old in out_dir.glob("*.pcap"):
        old.unlink()

    signatures = load_signatures(config_path)
    manifest = []
    for index, signature in enumerate(signatures, start=1):
        path, payload_len = write_pcap(signature, index, out_dir, args.src_ip, args.dst_ip, args.dst_port)
        manifest.append({
            "id": signature["id"],
            "name": signature["name"],
            "pcap": path.name,
            "payloadLength": payload_len,
        })

    with (out_dir / "manifest.json").open("w", encoding="utf-8") as fh:
        json.dump({"items": manifest}, fh, indent=2)
        fh.write("\n")

    print(f"generated {len(manifest)} pcaps in {out_dir}")


if __name__ == "__main__":
    main()
