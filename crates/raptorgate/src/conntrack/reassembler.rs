use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use crate::conntrack::proto::tcp::{seq_after, seq_after_eq};
use crate::data_plane::packet_context::PacketId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredChunk {
    pub packet_id: PacketId,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
struct BufferedSegment {
    packet_id: PacketId,
    data: Vec<u8>,
}

/// Stan reasemblacji jednego kierunku TCP (Original lub Reply)
#[derive(Debug)]
pub struct ReassemblyDirState {
    /// Następny oczekiwany seq. None do pierwszego pakietu z payloadem
    next_seq: Option<u32>,

    /// Bufor pakietów out-of-order: seq → segment z provenance
    out_of_order: BTreeMap<u32, BufferedSegment>,

    /// Ile bajtów w `out_of_order` — tani limit pamięci bez liczenia od nowa
    buffered: usize,
}

impl Default for ReassemblyDirState {
    fn default() -> Self {
        Self { next_seq: None, out_of_order: BTreeMap::new(), buffered: 0 }
    }
}

/// Para stanów [Original, Reply] trzymana w `ConntrackEntry`
#[derive(Debug, Default)]
pub struct ReassemblyState {
    pub dirs: [ReassemblyDirState; 2],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReassemblyConfig {
    pub enabled: bool,
    pub max_buffered_bytes: usize,
    pub max_segment_size: usize,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_buffered_bytes: 262_144,
            max_segment_size: 65_536,
        }
    }
}

pub fn feed(
    state: &mut ReassemblyDirState,
    cfg: &ReassemblyConfig,
    seq: u32,
    packet_id: PacketId,
    payload: &[u8],
) -> Vec<DeliveredChunk> {
    if !cfg.enabled || payload.is_empty() {
        return Vec::new();
    }

    if payload.len() > cfg.max_segment_size {
        return Vec::new();
    }

    let next = match state.next_seq {
        Some(n) => n,
        None => {
            state.next_seq = Some(seq.wrapping_add(payload.len() as u32));
            return vec![DeliveredChunk {
                packet_id,
                payload: payload.to_vec(),
            }];
        }
    };

    let end = seq.wrapping_add(payload.len() as u32);

    if seq_after_eq(next, end) {
        return Vec::new();
    }

    let (effective_seq, effective_data): (u32, &[u8]) = if seq_after(next, seq) {
        let drop_n = next.wrapping_sub(seq) as usize;

        if drop_n >= payload.len() {
            return Vec::new();
        }

        (next, &payload[drop_n..])
    } else {
        (seq, payload)
    };

    let mut out = Vec::new();

    if effective_seq == next {
        let mut cursor = next.wrapping_add(effective_data.len() as u32);

        out.push(DeliveredChunk {
            packet_id,
            payload: effective_data.to_vec(),
        });

        loop {
            let Some((&first_seq, _)) = state.out_of_order.first_key_value() else { break };

            if seq_after(first_seq, cursor) {
                break;
            }

            let (_, seg) = state.out_of_order.pop_first().unwrap();

            state.buffered = state.buffered.saturating_sub(seg.data.len());

            let seg_end = first_seq.wrapping_add(seg.data.len() as u32);

            if seq_after_eq(cursor, seg_end) {
                continue;
            }

            let drop_n = cursor.wrapping_sub(first_seq) as usize;

            let new_payload = seg.data[drop_n..].to_vec();

            cursor = cursor.wrapping_add(new_payload.len() as u32);

            out.push(DeliveredChunk {
                packet_id: seg.packet_id,
                payload: new_payload,
            });
        }

        state.next_seq = Some(cursor);
    } else {
        if state.buffered + effective_data.len() > cfg.max_buffered_bytes {
            return Vec::new();
        }

        let entry = state.out_of_order.entry(effective_seq).or_insert_with(|| BufferedSegment {
            packet_id,
            data: Vec::new(),
        });
        if entry.data.len() < effective_data.len() {
            state.buffered = state.buffered.saturating_sub(entry.data.len());
            entry.packet_id = packet_id;
            entry.data = effective_data.to_vec();
            state.buffered += entry.data.len();
        }
    }

    out
}

pub fn flush(state: &mut ReassemblyDirState) -> Vec<DeliveredChunk> {
    let chunks: Vec<DeliveredChunk> = state
        .out_of_order
        .values()
        .map(|seg| DeliveredChunk {
            packet_id: seg.packet_id,
            payload: seg.data.clone(),
        })
        .collect();

    state.out_of_order.clear();
    state.buffered = 0;

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ReassemblyConfig {
        ReassemblyConfig::default()
    }

    #[test]
    fn first_packet_establishes_baseline() {
        let mut s = ReassemblyDirState::default();
        let id = PacketId(1);
        let out = feed(&mut s, &cfg(), 1000, id, b"hello");

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].packet_id, id);
        assert_eq!(out[0].payload, b"hello");
        assert_eq!(s.next_seq, Some(1005));
    }

    #[test]
    fn in_order_packets_emit_each() {
        let mut s = ReassemblyDirState::default();

        feed(&mut s, &cfg(), 1000, PacketId(1), b"abc");

        let out = feed(&mut s, &cfg(), 1003, PacketId(2), b"def");

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].packet_id, PacketId(2));
        assert_eq!(out[0].payload, b"def");
    }

    #[test]
    fn out_of_order_held_then_drained_with_distinct_packet_ids() {
        let mut s = ReassemblyDirState::default();
        feed(&mut s, &cfg(), 1000, PacketId(1), b"abc");

        let out1 = feed(&mut s, &cfg(), 1006, PacketId(3), b"ghi");
        assert!(out1.is_empty());

        let out2 = feed(&mut s, &cfg(), 1003, PacketId(2), b"def");
        assert_eq!(out2.len(), 2);
        assert_eq!(out2[0].packet_id, PacketId(2));
        assert_eq!(out2[0].payload, b"def");
        assert_eq!(out2[1].packet_id, PacketId(3));
        assert_eq!(out2[1].payload, b"ghi");
        assert_eq!(s.next_seq, Some(1009));
    }

    #[test]
    fn pure_retransmit_dropped() {
        let mut s = ReassemblyDirState::default();

        feed(&mut s, &cfg(), 1000, PacketId(1), b"abc");

        let out = feed(&mut s, &cfg(), 1000, PacketId(2), b"abc");

        assert!(out.is_empty());
    }

    #[test]
    fn partial_overlap_left_takes_tail() {
        let mut s = ReassemblyDirState::default();

        feed(&mut s, &cfg(), 1000, PacketId(1), b"abc");

        let out = feed(&mut s, &cfg(), 1001, PacketId(2), b"bcd");

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].packet_id, PacketId(2));
        assert_eq!(out[0].payload, b"d");
        assert_eq!(s.next_seq, Some(1004));
    }

    #[test]
    fn wraparound_in_order() {
        let mut s = ReassemblyDirState::default();

        feed(&mut s, &cfg(), u32::MAX - 2, PacketId(1), b"ab");

        let out = feed(&mut s, &cfg(), u32::MAX, PacketId(2), b"cd");

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, b"cd");
        assert_eq!(s.next_seq, Some(1));
    }

    #[test]
    fn limit_drops_out_of_order_segment() {
        let mut c = cfg();
        c.max_buffered_bytes = 8;

        let mut s = ReassemblyDirState::default();

        feed(&mut s, &c, 1000, PacketId(1), b"abcd");
        feed(&mut s, &c, 1100, PacketId(2), &[0xaa; 4]);
        feed(&mut s, &c, 1200, PacketId(3), &[0xbb; 4]);

        let out = feed(&mut s, &c, 1300, PacketId(4), &[0xcc; 4]);

        assert!(out.is_empty());
        assert_eq!(s.buffered, 8);
    }
}
