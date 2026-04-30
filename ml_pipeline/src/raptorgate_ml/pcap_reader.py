from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from scapy.all import IP, IPv6, TCP, UDP, PcapReader, Raw
from scapy.packet import Packet


@dataclass
class ParsedPacket:
    ts: float
    ip_version: int
    ip_proto: int
    ttl: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload_len: int
    payload: bytes
    tcp_flags: int | None
    tcp_window: int | None


_TCP_SYN = 0x02
_TCP_ACK = 0x10
_TCP_FIN = 0x01
_TCP_RST = 0x04
_TCP_PSH = 0x08


def _flag(flags: int | None, bit: int) -> bool:
    return bool(flags) and (flags & bit) != 0


def is_syn(flags: int | None) -> bool:
    return _flag(flags, _TCP_SYN) and not _flag(flags, _TCP_ACK)


def has(flags: int | None, mask: int) -> bool:
    return _flag(flags, mask)


def syn_bit() -> int:
    return _TCP_SYN


def ack_bit() -> int:
    return _TCP_ACK


def fin_bit() -> int:
    return _TCP_FIN


def rst_bit() -> int:
    return _TCP_RST


def psh_bit() -> int:
    return _TCP_PSH


def iter_packets(pcap_path: Path) -> Iterator[ParsedPacket]:
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            parsed = _parse(pkt)
            if parsed is not None:
                yield parsed


def _parse(pkt: Packet) -> ParsedPacket | None:
    ts = float(pkt.time) if hasattr(pkt, "time") else 0.0

    if IP in pkt:
        ip = pkt[IP]
        ip_version = 4
        ttl = int(ip.ttl)
        src_ip, dst_ip = ip.src, ip.dst
        ip_proto = int(ip.proto)
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        ip_version = 6
        ttl = int(ip6.hlim)
        src_ip, dst_ip = ip6.src, ip6.dst
        ip_proto = int(ip6.nh)
    else:
        return None

    src_port = dst_port = 0
    tcp_flags: int | None = None
    tcp_window: int | None = None
    payload = b""

    if TCP in pkt:
        t = pkt[TCP]
        src_port = int(t.sport)
        dst_port = int(t.dport)
        tcp_flags = int(t.flags)
        tcp_window = int(t.window)
        if Raw in t:
            payload = bytes(t[Raw].load)
    elif UDP in pkt:
        u = pkt[UDP]
        src_port = int(u.sport)
        dst_port = int(u.dport)
        if Raw in u:
            payload = bytes(u[Raw].load)

    return ParsedPacket(
        ts=ts,
        ip_version=ip_version,
        ip_proto=ip_proto,
        ttl=ttl,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        payload_len=len(payload),
        payload=payload,
        tcp_flags=tcp_flags,
        tcp_window=tcp_window,
    )
