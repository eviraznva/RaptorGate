use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;
pub const TCP_FLAG_ECE: u8 = 0x40;
pub const TCP_FLAG_CWR: u8 = 0x80;

#[derive(Debug, Clone)]
pub struct ParsedPacket<'a> {
    pub ts: f64,
    pub ip_version: u8,
    pub ip_proto: u8,
    pub ttl: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
    pub tcp_flags: Option<u8>,
    pub tcp_window: Option<u16>,
}

pub fn parse_ethernet(ts: f64, data: &[u8]) -> Option<ParsedPacket<'_>> {
    let sliced = SlicedPacket::from_ethernet(data).ok()?;
    finalize(ts, sliced)
}

pub fn parse_linux_sll(ts: f64, data: &[u8]) -> Option<ParsedPacket<'_>> {
    let sliced = SlicedPacket::from_linux_sll(data).ok()?;
    finalize(ts, sliced)
}

pub fn parse_ip(ts: f64, data: &[u8]) -> Option<ParsedPacket<'_>> {
    let sliced = SlicedPacket::from_ip(data).ok()?;
    finalize(ts, sliced)
}

fn finalize(ts: f64, sliced: SlicedPacket<'_>) -> Option<ParsedPacket<'_>> {
    let net = sliced.net?;
    let (ip_version, ip_proto, ttl, src_ip, dst_ip) = match net {
        NetSlice::Ipv4(ipv4) => {
            let header = ipv4.header();
            (
                4u8,
                header.protocol().0,
                header.ttl(),
                IpAddr::V4(header.source_addr()),
                IpAddr::V4(header.destination_addr()),
            )
        }
        NetSlice::Ipv6(ipv6) => {
            let header = ipv6.header();
            (
                6u8,
                header.next_header().0,
                header.hop_limit(),
                IpAddr::V6(header.source_addr()),
                IpAddr::V6(header.destination_addr()),
            )
        }
        NetSlice::Arp(_) => return None,
    };

    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut payload: &[u8] = &[];
    let mut tcp_flags: Option<u8> = None;
    let mut tcp_window: Option<u16> = None;

    match sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            src_port = tcp.source_port();
            dst_port = tcp.destination_port();
            payload = tcp.payload();
            let mut flags = 0u8;
            if tcp.fin() {
                flags |= TCP_FLAG_FIN;
            }
            if tcp.syn() {
                flags |= TCP_FLAG_SYN;
            }
            if tcp.rst() {
                flags |= TCP_FLAG_RST;
            }
            if tcp.psh() {
                flags |= TCP_FLAG_PSH;
            }
            if tcp.ack() {
                flags |= TCP_FLAG_ACK;
            }
            if tcp.urg() {
                flags |= TCP_FLAG_URG;
            }
            if tcp.ece() {
                flags |= TCP_FLAG_ECE;
            }
            if tcp.cwr() {
                flags |= TCP_FLAG_CWR;
            }
            tcp_flags = Some(flags);
            tcp_window = Some(tcp.window_size());
        }
        Some(TransportSlice::Udp(udp)) => {
            src_port = udp.source_port();
            dst_port = udp.destination_port();
            payload = udp.payload();
        }
        _ => {}
    }

    Some(ParsedPacket {
        ts,
        ip_version,
        ip_proto,
        ttl,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
        tcp_flags,
        tcp_window,
    })
}

pub fn is_syn(flags: u8) -> bool {
    (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0
}

pub fn is_syn_ack(flags: u8) -> bool {
    (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) != 0
}
