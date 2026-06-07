//! Integration tests for the packet parser.
//!
//! Per the project plan, pcap fixtures are built in-memory with
//! `etherparse::PacketBuilder` inside each test body; nothing is loaded
//! from disk.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{PacketBuilder, TcpOptionElement};
use raptorgate_pcap::parse::{
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_SYN, is_syn, parse_ethernet, parse_ip,
    parse_linux_sll,
};

const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

fn build_ipv4_tcp_syn(payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(12345, 443, 1, 65535)
        .syn();
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

fn build_ipv4_tcp_psh_ack(payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(12345, 443, 2, 65535)
        .psh()
        .ack(100);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

fn build_ipv4_udp_dns(payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
        .ipv4([1, 2, 3, 4], [8, 8, 8, 8], 64)
        .udp(33333, 53);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

fn build_ipv6_tcp(payload: &[u8]) -> Vec<u8> {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets();
    let builder = PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
        .ipv6(src, dst, 32)
        .tcp(54321, 80, 1, 8192)
        .ack(0);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).unwrap();
    out
}

#[test]
fn parses_ipv4_tcp_syn() {
    let bytes = build_ipv4_tcp_syn(&[]);
    let p = parse_ethernet(123.456, &bytes).expect("packet should parse");

    assert_eq!(p.ts, 123.456);
    assert_eq!(p.ip_version, 4);
    assert_eq!(p.ip_proto, 6);
    assert_eq!(p.ttl, 64);
    assert_eq!(p.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(p.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(p.src_port, 12345);
    assert_eq!(p.dst_port, 443);
    assert_eq!(p.payload.len(), 0);

    let flags = p.tcp_flags.expect("tcp flags should be set");
    assert_eq!(flags & TCP_FLAG_SYN, TCP_FLAG_SYN);
    assert_eq!(flags & TCP_FLAG_ACK, 0);
    assert!(is_syn(flags));
    assert_eq!(p.tcp_window, Some(65535));
}

#[test]
fn parses_ipv4_tcp_payload_with_psh_ack() {
    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let bytes = build_ipv4_tcp_psh_ack(payload);
    let p = parse_ethernet(0.0, &bytes).expect("packet should parse");

    assert_eq!(p.ip_proto, 6);
    assert_eq!(p.payload, payload.as_slice());

    let flags = p.tcp_flags.expect("tcp flags should be set");
    assert_eq!(flags & TCP_FLAG_PSH, TCP_FLAG_PSH);
    assert_eq!(flags & TCP_FLAG_ACK, TCP_FLAG_ACK);
    assert!(!is_syn(flags));
}

#[test]
fn parses_ipv4_tcp_fin_ack() {
    let builder = PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(12345, 443, 50, 4096)
        .fin()
        .ack(100);
    let mut bytes = Vec::with_capacity(builder.size(0));
    builder.write(&mut bytes, &[]).unwrap();

    let p = parse_ethernet(1.0, &bytes).expect("packet should parse");
    let flags = p.tcp_flags.expect("flags");
    assert_eq!(flags & TCP_FLAG_FIN, TCP_FLAG_FIN);
    assert_eq!(flags & TCP_FLAG_ACK, TCP_FLAG_ACK);
}

#[test]
fn parses_ipv4_udp_dns_payload() {
    let payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let bytes = build_ipv4_udp_dns(payload);
    let p = parse_ethernet(1.0, &bytes).expect("packet should parse");

    assert_eq!(p.ip_version, 4);
    assert_eq!(p.ip_proto, 17);
    assert_eq!(p.src_ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(p.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(p.src_port, 33333);
    assert_eq!(p.dst_port, 53);
    assert_eq!(p.payload, payload.as_slice());
    assert!(p.tcp_flags.is_none());
    assert!(p.tcp_window.is_none());
}

#[test]
fn parses_ipv6_tcp() {
    let bytes = build_ipv6_tcp(&[0xaa, 0xbb, 0xcc]);
    let p = parse_ethernet(2.0, &bytes).expect("packet should parse");

    assert_eq!(p.ip_version, 6);
    assert_eq!(p.ip_proto, 6);
    assert_eq!(p.ttl, 32);
    assert_eq!(
        p.src_ip,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    );
    assert_eq!(p.src_port, 54321);
    assert_eq!(p.dst_port, 80);
    assert_eq!(p.payload, &[0xaa, 0xbb, 0xcc]);
}

#[test]
fn parses_raw_ip_without_link_layer() {
    let builder = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(1000, 53);
    let mut bytes = Vec::with_capacity(builder.size(0));
    builder.write(&mut bytes, &[]).unwrap();

    let p = parse_ip(0.0, &bytes).expect("packet should parse");
    assert_eq!(p.ip_version, 4);
    assert_eq!(p.ip_proto, 17);
    assert_eq!(p.src_port, 1000);
    assert_eq!(p.dst_port, 53);
}

#[test]
fn non_ip_returns_none() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&DST_MAC);
    bytes.extend_from_slice(&SRC_MAC);
    bytes.extend_from_slice(&[0x88, 0xb5]);
    bytes.extend_from_slice(&[0; 46]);

    assert!(parse_ethernet(0.0, &bytes).is_none());
}

#[test]
fn truncated_packet_returns_none() {
    let bytes = build_ipv4_tcp_syn(&[]);
    let truncated = &bytes[..20];
    assert!(parse_ethernet(0.0, truncated).is_none());
}

#[test]
fn linux_sll_ipv4_tcp() {
    let mut sll = Vec::new();
    sll.extend_from_slice(&0u16.to_be_bytes());
    sll.extend_from_slice(&1u16.to_be_bytes());
    sll.extend_from_slice(&6u16.to_be_bytes());
    sll.extend_from_slice(&[0u8; 8]);
    sll.extend_from_slice(&0x0800u16.to_be_bytes());

    let inner = PacketBuilder::ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).tcp(12345, 443, 1, 65535);
    let mut ip_tcp = Vec::with_capacity(inner.size(0));
    inner.write(&mut ip_tcp, &[]).unwrap();
    sll.extend_from_slice(&ip_tcp);

    let p = parse_linux_sll(0.0, &sll).expect("packet should parse");
    assert_eq!(p.ip_version, 4);
    assert_eq!(p.ip_proto, 6);
    assert_eq!(p.dst_port, 443);
}

#[test]
fn tcp_options_present_does_not_break_payload_offset() {
    let payload = b"hello";
    let builder = PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(12345, 443, 1, 65535)
        .options(&[
            TcpOptionElement::MaximumSegmentSize(1460),
            TcpOptionElement::Noop,
        ])
        .unwrap();
    let mut bytes = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut bytes, payload).unwrap();

    let p = parse_ethernet(0.0, &bytes).expect("packet should parse");
    assert_eq!(p.payload, payload.as_slice());
}
