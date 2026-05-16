use std::net::IpAddr;
use std::sync::Arc;

use etherparse::PacketBuilder;

use crate::conntrack::entry::ConntrackEntry;
use crate::conntrack::proto::tcp::{TcpConntrack, TcpProtoState};
use crate::conntrack::tuple::Direction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResetSegment {
    pub direction: Direction,
    pub seq: u32,
    pub ack: u32,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub zone: u16,
    pub ingress_iface: Option<Arc<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpResetUnavailable {
    HandshakeIncomplete,
    MissingSequenceState,
    ConnectionAlreadyClosed,
    NotTcpProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpResetAction {
    EmitRstPair {
        original: TcpResetSegment,
        reply: TcpResetSegment,
    },
    Unavailable {
        reason: TcpResetUnavailable,
    },
}

pub struct TcpResetBuilder;

impl TcpResetBuilder {
    pub fn from_entry(entry: &ConntrackEntry, tcp: &TcpProtoState) -> TcpResetAction {
        if matches!(tcp.state, TcpConntrack::Close) {
            return TcpResetAction::Unavailable {
                reason: TcpResetUnavailable::ConnectionAlreadyClosed,
            };
        }

        if !matches!(
            tcp.state,
            TcpConntrack::Established
                | TcpConntrack::FinWait
                | TcpConntrack::CloseWait
                | TcpConntrack::LastAck
                | TcpConntrack::TimeWait
        ) {
            return TcpResetAction::Unavailable {
                reason: TcpResetUnavailable::HandshakeIncomplete,
            };
        }

        let orig = &tcp.seen[0];
        let rep = &tcp.seen[1];

        if orig.last_seq == 0 || rep.last_seq == 0 {
            return TcpResetAction::Unavailable {
                reason: TcpResetUnavailable::MissingSequenceState,
            };
        }

        let path = entry.interface_path();
        let orig_t = entry.original;
        let reply_t = entry.reply();

        let original = TcpResetSegment {
            direction: Direction::Original,
            seq: orig.last_seq,
            ack: orig.last_ack,
            src_ip: orig_t.src_ip,
            dst_ip: orig_t.dst_ip,
            src_port: orig_t.src_port,
            dst_port: orig_t.dst_port,
            zone: orig_t.zone,
            ingress_iface: path.original_ingress.clone(),
        };

        let reply = TcpResetSegment {
            direction: Direction::Reply,
            seq: rep.last_seq,
            ack: rep.last_ack,
            src_ip: reply_t.src_ip,
            dst_ip: reply_t.dst_ip,
            src_port: reply_t.src_port,
            dst_port: reply_t.dst_port,
            zone: reply_t.zone,
            ingress_iface: path.reply_ingress.clone(),
        };

        TcpResetAction::EmitRstPair { original, reply }
    }
}

pub fn tcp_reset_segment_to_raw(seg: &TcpResetSegment) -> Option<Vec<u8>> {
    let (src_ip, dst_ip) = match (seg.src_ip, seg.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
        _ => return None,
    };
    let mut packet = Vec::new();
    PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4(src_ip.octets(), dst_ip.octets(), 64)
        .tcp(seg.src_port, seg.dst_port, seg.seq, 0)
        .ack(seg.ack)
        .rst()
        .write(&mut packet, &[])
        .ok()?;
    Some(packet)
}
