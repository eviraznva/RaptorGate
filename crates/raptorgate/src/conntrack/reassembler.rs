use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use crate::conntrack::proto::tcp::{seq_after, seq_after_eq};
use crate::data_plane::packet_context::PacketId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredChunk {
    pub packet_id: PacketId,
    pub payload: Vec<u8>,
    pub tcp_payload_start_seq: u32,
}

#[derive(Debug)]
struct BufferedSegment {
    packet_id: PacketId,
    start_seq: u32,
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

fn segment_end(start: u32, len: usize) -> u32 {
    start.wrapping_add(len as u32)
}

fn segments_overlap(a_start: u32, a_len: usize, b_start: u32, b_len: usize) -> bool {
    let a_end = segment_end(a_start, a_len);
    let b_end = segment_end(b_start, b_len);
    !(seq_after_eq(a_start, b_end) || seq_after_eq(b_start, a_end))
}

fn remove_buffered(state: &mut ReassemblyDirState, key: u32) {
    if let Some(seg) = state.out_of_order.remove(&key) {
        state.buffered = state.buffered.saturating_sub(seg.data.len());
    }
}

fn buffer_segment(
    state: &mut ReassemblyDirState,
    packet_id: PacketId,
    mut seq: u32,
    mut data: Vec<u8>,
) -> bool {
    if data.is_empty() {
        return true;
    }

    loop {
        let end = segment_end(seq, data.len());
        let Some((&existing_start, existing)) = state
            .out_of_order
            .range(..=seq)
            .next_back()
            .filter(|&(&k, seg)| segments_overlap(k, seg.data.len(), seq, data.len()))
        else {
            break;
        };

        let existing_end = segment_end(existing_start, existing.data.len());
        if seq_after_eq(existing_start, seq) && seq_after(existing_end, seq) {
            if seq_after_eq(existing_end, end) {
                return true;
            }
            let trim = existing_end.wrapping_sub(seq) as usize;
            if trim >= data.len() {
                return true;
            }
            seq = existing_end;
            data = data.split_off(trim);
        } else {
            break;
        }
    }

    if data.is_empty() {
        return true;
    }

    let end = segment_end(seq, data.len());

    let fully_covered: Vec<u32> = state
        .out_of_order
        .iter()
        .filter(|&(&k, seg)| {
            let seg_end = segment_end(k, seg.data.len());
            seq_after_eq(seq, k) && seq_after_eq(seg_end, end)
        })
        .map(|(&k, _)| k)
        .collect();
    for k in fully_covered {
        remove_buffered(state, k);
    }

    let overlapping: Vec<u32> = state
        .out_of_order
        .iter()
        .filter(|&(&k, seg)| segments_overlap(k, seg.data.len(), seq, data.len()))
        .map(|(&k, _)| k)
        .collect();

    for key in overlapping {
        let (seg_start, seg_end, seg_len) = {
            let seg = &state.out_of_order[&key];
            (key, segment_end(key, seg.data.len()), seg.data.len())
        };

        if seq_after(seg_start, seq) && seq_after(end, seg_start) && seq_after(seg_end, end) {
            let trim = end.wrapping_sub(seg_start) as usize;
            let seg = state.out_of_order.get_mut(&key).unwrap();
            state.buffered = state.buffered.saturating_sub(seg_len);
            seg.data = seg.data.split_off(trim);
            seg.start_seq = end;
            let new_len = seg.data.len();
            let new_start = end;
            let pid = seg.packet_id;
            let tail = std::mem::take(&mut seg.data);
            remove_buffered(state, key);
            if !tail.is_empty() {
                state.buffered += new_len;
                state.out_of_order.insert(
                    new_start,
                    BufferedSegment {
                        packet_id: pid,
                        start_seq: new_start,
                        data: tail,
                    },
                );
            }
        } else if seq_after_eq(seq, seg_start) && seq_after(seg_end, end) {
            let keep = seg_end.wrapping_sub(end) as usize;
            let seg = state.out_of_order.get_mut(&key).unwrap();
            state.buffered = state.buffered.saturating_sub(seg_len);
            seg.data.truncate(seg_len - keep);
            state.buffered += seg.data.len();
        }
    }

    if let Some((&k, _)) = state.out_of_order.range(seq..).next() {
        if seq_after(k, seq) && seq_after(end, k) {
            let trim = end.wrapping_sub(k) as usize;
            if trim >= data.len() {
                return true;
            }
            data.truncate(data.len() - trim);
        }
    }

    if data.is_empty() {
        return true;
    }

    if let Some(existing) = state.out_of_order.get(&seq) {
        if existing.data.len() >= data.len() {
            return true;
        }
        state.buffered = state.buffered.saturating_sub(existing.data.len());
    }
    state.buffered += data.len();

    state.out_of_order.insert(
        seq,
        BufferedSegment {
            packet_id,
            start_seq: seq,
            data,
        },
    );

    true
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

    let len = payload.len();
    let end = segment_end(seq, len);
    let next = state.next_seq;
    let buffered = state.buffered;

    if payload.len() > cfg.max_segment_size {
        tracing::debug!(
            event = "reassembler.oversize_drop",
            seq,
            end,
            len,
            next = ?next,
            packet_id = packet_id.0,
            buffered,
        );
        return Vec::new();
    }

    let next = match state.next_seq {
        Some(n) => n,
        None => {
            state.next_seq = Some(end);
            tracing::trace!(
                event = "reassembler.baseline",
                seq,
                end,
                len,
                next = ?None::<u32>,
                packet_id = packet_id.0,
                buffered,
            );
            return vec![DeliveredChunk {
                packet_id,
                payload: payload.to_vec(),
                tcp_payload_start_seq: seq,
            }];
        }
    };

    if seq_after_eq(next, end) {
        tracing::trace!(
            event = "reassembler.retransmit_drop",
            seq,
            end,
            len,
            next,
            packet_id = packet_id.0,
            buffered,
        );
        return Vec::new();
    }

    let (effective_seq, effective_data, drop_n): (u32, &[u8], usize) = if seq_after(next, seq) {
        let drop_n = next.wrapping_sub(seq) as usize;

        if drop_n >= payload.len() {
            tracing::trace!(
                event = "reassembler.retransmit_drop",
                seq,
                end,
                len,
                next,
                packet_id = packet_id.0,
                buffered,
                drop_n,
            );
            return Vec::new();
        }

        tracing::trace!(
            event = "reassembler.left_trim",
            seq,
            end,
            len,
            next,
            packet_id = packet_id.0,
            buffered,
            drop_n,
        );
        (next, &payload[drop_n..], drop_n)
    } else {
        (seq, payload, 0)
    };

    let mut out = Vec::new();

    if effective_seq == next {
        remove_buffered(state, next);
        let drain_anchor = next;
        let mut cursor = segment_end(next, effective_data.len());

        tracing::trace!(
            event = "reassembler.inorder_emit",
            seq,
            end,
            len,
            next,
            packet_id = packet_id.0,
            buffered,
            emit_len = effective_data.len(),
            drop_n,
        );

        out.push(DeliveredChunk {
            packet_id,
            payload: effective_data.to_vec(),
            tcp_payload_start_seq: next,
        });

        loop {
            let Some((&first_seq, _)) = state.out_of_order.first_key_value() else { break };

            if seq_after(first_seq, cursor) {
                break;
            }

            let (_, seg) = state.out_of_order.pop_first().unwrap();

            state.buffered = state.buffered.saturating_sub(seg.data.len());

            let seg_end = segment_end(first_seq, seg.data.len());

            if first_seq < cursor {
                if first_seq < drain_anchor {
                    let gap_end = drain_anchor.min(seg_end);
                    let gap_len = gap_end.wrapping_sub(first_seq) as usize;
                    if gap_len > 0 && gap_len <= seg.data.len() {
                        let gap_payload = seg.data[..gap_len].to_vec();
                        tracing::trace!(
                            event = "reassembler.drain_emit",
                            seq,
                            end,
                            len,
                            next = drain_anchor,
                            packet_id = packet_id.0,
                            buffered = state.buffered,
                            first_seq,
                            seg_end,
                            cursor,
                            drop_n = 0usize,
                            emit_len = gap_payload.len(),
                        );
                        out.push(DeliveredChunk {
                            packet_id: seg.packet_id,
                            payload: gap_payload,
                            tcp_payload_start_seq: first_seq,
                        });
                    }
                }
                if seq_after(seg_end, cursor) {
                    let tail_off = cursor.wrapping_sub(first_seq) as usize;
                    if tail_off < seg.data.len() {
                        let tail = seg.data[tail_off..].to_vec();
                        state.buffered += tail.len();
                        state.out_of_order.insert(
                            cursor,
                            BufferedSegment {
                                packet_id: seg.packet_id,
                                start_seq: cursor,
                                data: tail,
                            },
                        );
                    }
                    break;
                }
                continue;
            }

            if seq_after_eq(cursor, seg_end) {
                debug_assert!(
                    first_seq >= drain_anchor || seg.data.is_empty(),
                    "drain_skip_dup: first_seq={first_seq} drain_anchor={drain_anchor} \
                     seg_end={seg_end} cursor={cursor} would skip un-emitted bytes"
                );
                tracing::debug!(
                    event = "reassembler.drain_skip_dup",
                    seq,
                    end,
                    len,
                    next = drain_anchor,
                    packet_id = packet_id.0,
                    buffered = state.buffered,
                    first_seq,
                    seg_end,
                    cursor,
                );
                continue;
            }

            debug_assert_eq!(
                first_seq, cursor,
                "drain_emit: expected contiguous segment at cursor={cursor}, got first_seq={first_seq}"
            );

            let new_payload = seg.data;
            let emit_len = new_payload.len();

            tracing::trace!(
                event = "reassembler.drain_emit",
                seq,
                end,
                len,
                next = drain_anchor,
                packet_id = packet_id.0,
                buffered = state.buffered,
                first_seq,
                seg_end,
                cursor,
                drop_n = 0usize,
                emit_len,
            );

            cursor = segment_end(cursor, emit_len);

            out.push(DeliveredChunk {
                packet_id: seg.packet_id,
                payload: new_payload,
                tcp_payload_start_seq: first_seq,
            });
        }

        state.next_seq = Some(cursor);
    } else {
        if state.buffered + effective_data.len() > cfg.max_buffered_bytes {
            tracing::debug!(
                event = "reassembler.over_budget_drop",
                seq,
                end,
                len,
                next,
                packet_id = packet_id.0,
                buffered,
            );
            return Vec::new();
        }

        let replaced = state.out_of_order.contains_key(&effective_seq);
        if !buffer_segment(state, packet_id, effective_seq, effective_data.to_vec()) {
            tracing::debug!(
                event = "reassembler.over_budget_drop",
                seq,
                end,
                len,
                next,
                packet_id = packet_id.0,
                buffered = state.buffered,
            );
            return Vec::new();
        }

        tracing::trace!(
            event = if replaced {
                "reassembler.buffer_replace"
            } else {
                "reassembler.buffer"
            },
            seq,
            end,
            len,
            next,
            packet_id = packet_id.0,
            buffered = state.buffered,
            effective_seq,
            effective_len = effective_data.len(),
        );
    }

    out
}

pub fn flush(state: &mut ReassemblyDirState) -> Vec<DeliveredChunk> {
    let chunks: Vec<DeliveredChunk> = state
        .out_of_order
        .values()
        .map(|seg| {
            tracing::trace!(
                event = "reassembler.flush_emit",
                seq = seg.start_seq,
                end = segment_end(seg.start_seq, seg.data.len()),
                len = seg.data.len(),
                next = ?state.next_seq,
                packet_id = seg.packet_id.0,
                buffered = state.buffered,
            );
            DeliveredChunk {
                packet_id: seg.packet_id,
                payload: seg.data.clone(),
                tcp_payload_start_seq: seg.start_seq,
            }
        })
        .collect();

    state.out_of_order.clear();
    state.buffered = 0;

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::seq::SliceRandom;
    use rand::{Rng, SeedableRng};

    fn cfg() -> ReassemblyConfig {
        ReassemblyConfig::default()
    }

    fn collect_delivered(chunks: &[DeliveredChunk]) -> Vec<u8> {
        chunks.iter().flat_map(|c| c.payload.iter().copied()).collect()
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

    #[test]
    fn out_of_order_then_overlapping_retransmit_delivers_all() {
        let base = 1000u32;
        let banner = b"SSH-2.0-RaptorGate\r\n".to_vec();
        let kexinit = vec![0x15u8; 1120];
        let dh_reply = vec![0x42u8; 1448];

        let mut stream = Vec::new();
        stream.extend_from_slice(&banner);
        stream.extend_from_slice(&kexinit);
        stream.extend_from_slice(&dh_reply);

        let off_kex = banner.len() as u32;
        let off_dh = off_kex + kexinit.len() as u32;
        let split = 637usize;

        let mut s = ReassemblyDirState::default();
        let c = cfg();
        let mut delivered = Vec::new();

        delivered.extend(collect_delivered(&feed(
            &mut s,
            &c,
            base,
            PacketId(1),
            &banner,
        )));
        delivered.extend(collect_delivered(&feed(
            &mut s,
            &c,
            base.wrapping_add(off_kex),
            PacketId(2),
            &kexinit,
        )));

        feed(
            &mut s,
            &c,
            base.wrapping_add(off_dh + split as u32),
            PacketId(20),
            &dh_reply[split..],
        );
        delivered.extend(collect_delivered(&feed(
            &mut s,
            &c,
            base.wrapping_add(off_dh),
            PacketId(21),
            &dh_reply[..split],
        )));
        delivered.extend(collect_delivered(&feed(
            &mut s,
            &c,
            base.wrapping_add(off_dh + split as u32),
            PacketId(22),
            &dh_reply[split..],
        )));

        assert_eq!(
            delivered,
            stream,
            "DH_REPLY must be delivered despite overlapping re-segmented retransmit"
        );
    }

    #[test]
    fn buffered_spanning_segment_prefix_recovered_on_drain() {
        let base = 1000u32;
        let mut s = ReassemblyDirState::default();
        let c = cfg();
        let mut delivered = Vec::new();

        delivered.extend(collect_delivered(&feed(
            &mut s,
            &c,
            base,
            PacketId(1),
            &vec![0xAA; 163],
        )));

        let spanning = vec![0xCC; 911];
        feed(
            &mut s,
            &c,
            base.wrapping_add(163 + 637 - 100),
            PacketId(3),
            &spanning,
        );

        delivered.extend(collect_delivered(&feed(
            &mut s,
            &c,
            base.wrapping_add(163),
            PacketId(2),
            &vec![0xBB; 637],
        )));
        delivered.extend(collect_delivered(&feed(
            &mut s,
            &c,
            base.wrapping_add(163 + 637),
            PacketId(4),
            &vec![0xDD; 811],
        )));

        let mut expected = vec![0xAA; 163];
        expected.extend(vec![0xBB; 637]);
        expected.extend(vec![0xDD; 811]);
        assert_eq!(delivered, expected);
    }

    #[test]
    fn reconstruct_stream_lossless() {
        const BASE: u32 = 50_000;
        const STREAM_LEN: usize = 8192;
        const ROUNDS: u32 = 200;

        let original: Vec<u8> = (0..STREAM_LEN).map(|i| (i % 251) as u8).collect();

        for seed in 0..ROUNDS {
            let mut rng = StdRng::seed_from_u64(seed as u64);

            let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
            let mut offset = 0usize;
            while offset < STREAM_LEN {
                let max_chunk = (STREAM_LEN - offset).min(1400);
                let chunk_len = rng.gen_range(1..=max_chunk);
                segments.push((offset as u32, original[offset..offset + chunk_len].to_vec()));
                offset += chunk_len;
            }

            let mut state = ReassemblyDirState::default();
            let c = cfg();
            let mut delivered = Vec::new();
            let mut packet_id = 1u64;

            delivered.extend(collect_delivered(&feed(
                &mut state,
                &c,
                BASE,
                PacketId(packet_id),
                &segments[0].1,
            )));
            packet_id += 1;

            let mut rest: Vec<(u32, Vec<u8>)> = segments[1..].to_vec();
            let mut extras: Vec<(u32, Vec<u8>)> = Vec::new();
            for (off, data) in &rest {
                if rng.gen_bool(0.3) {
                    extras.push((*off, data.clone()));
                }
                if rng.gen_bool(0.25) && data.len() > 1 {
                    let split = rng.gen_range(1..data.len());
                    extras.push((*off, data[..split].to_vec()));
                    extras.push((off.wrapping_add(split as u32), data[split..].to_vec()));
                }
            }
            rest.extend(extras);
            rest.shuffle(&mut rng);

            for (off, data) in rest {
                delivered.extend(collect_delivered(&feed(
                    &mut state,
                    &c,
                    BASE.wrapping_add(off),
                    PacketId(packet_id),
                    &data,
                )));
                packet_id += 1;
            }

            let next_off = state.next_seq.unwrap().wrapping_sub(BASE) as usize;
            assert_eq!(
                delivered,
                original[..next_off.min(STREAM_LEN)],
                "seed {seed}: delivered bytes must equal original stream prefix up to next_seq"
            );
        }
    }
}
