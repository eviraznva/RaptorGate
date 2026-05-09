use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use crate::conntrack::proto::tcp::{seq_after, seq_after_eq};

/// Stan reasemblacji jednego kierunku TCP (Original lub Reply)
#[derive(Debug)]
pub struct ReassemblyDirState {
    /// Następny oczekiwany seq. None do pierwszego pakietu z payloadem
    next_seq: Option<u32>,

    /// Bufor pakietów out-of-order: seq → payload od tego seq
    /// BTreeMap zapewnia iterację rosnącą po seq dla łączenia sąsiadujących segmentów
    out_of_order: BTreeMap<u32, Vec<u8>>,

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
    pub max_buffered_bytes: usize, // per direction
    pub max_segment_size: usize,   // pojedynczy pakiet, drop jeśli większy
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_buffered_bytes: 262_144, // 256 KiB
            max_segment_size: 65_536,
        }
    }
}

pub fn feed(state: &mut ReassemblyDirState, cfg: &ReassemblyConfig, seq: u32, payload: &[u8]) -> Vec<Vec<u8>> {
    if !cfg.enabled || payload.is_empty() {
        return Vec::new();
    }

    if payload.len() > cfg.max_segment_size {
        // Pakiet większy niż limit — odrzuć cały, traktuj jak hole
        return Vec::new();
    }

    // Pierwszy pakiet z payloadem ustala bazę
    let next = match state.next_seq {
        Some(n) => n,
        None => {
            state.next_seq = Some(seq.wrapping_add(payload.len() as u32));
            return vec![payload.to_vec()];
        }
    };

    let end = seq.wrapping_add(payload.len() as u32);

    // Pakiet w całości za już-doręczonym koncem — czysta retransmisja
    if seq_after_eq(next, end) {
        return Vec::new();
    }

    // Częściowe nakładanie z lewej: weź ogon `[next..end]`
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
        // Hit — emit od razu i sprawdź łączenie z out_of_order
        let mut cursor = next.wrapping_add(effective_data.len() as u32);
        
        out.push(effective_data.to_vec());

        // Drenuj out_of_order: sąsiadujące lub overlapping segmenty
        loop {
            let Some((&first_seq, _)) = state.out_of_order.first_key_value() else { break };

            if seq_after(first_seq, cursor) {
                // Hole — kolejny segment zaczyna się dalej
                break;
            }
            
            let (_, data) = state.out_of_order.pop_first().unwrap();
            
            state.buffered = state.buffered.saturating_sub(data.len());

            let seg_end = first_seq.wrapping_add(data.len() as u32);
            
            if seq_after_eq(cursor, seg_end) {
                // Cały duplikat — pomiń
                continue;
            }

            let drop_n = cursor.wrapping_sub(first_seq) as usize;
            
            let new_chunk = data[drop_n..].to_vec();
            
            cursor = cursor.wrapping_add(new_chunk.len() as u32);
            
            out.push(new_chunk);
        }

        state.next_seq = Some(cursor);
    } else {
        // Out-of-order — wstaw do mapy jeśli mieści się w budżecie.
        if state.buffered + effective_data.len() > cfg.max_buffered_bytes {
            // Brak miejsca — najprostsza polityka: drop tego segmentu
            // Nie advansujemy next_seq żeby nie zgubić streamu po stronie subscribera
            return Vec::new();
        }

        // Jeśli kolidujący seq już istnieje, zachowaj większy — typowo retransmit ten sam.
        let entry = state.out_of_order.entry(effective_seq).or_default();
        if entry.len() < effective_data.len() {
            state.buffered = state.buffered.saturating_sub(entry.len());
            *entry = effective_data.to_vec();
            state.buffered += entry.len();
        }
    }

    out
}

/// Wymusza wyrzucenie buforu out-of-order (np. na FIN/RST) — emituje wszystko
/// co jest, akceptując dziury jako koniec strumienia
pub fn flush(state: &mut ReassemblyDirState) -> Vec<Vec<u8>> {
    let chunks: Vec<Vec<u8>> = state.out_of_order.values().cloned().collect();
    
    state.out_of_order.clear();
    
    state.buffered = 0;
    
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ReassemblyConfig { ReassemblyConfig::default() }

    #[test]
    fn first_packet_establishes_baseline() {
        let mut s = ReassemblyDirState::default();
        let out = feed(&mut s, &cfg(), 1000, b"hello");
        
        assert_eq!(out, vec![b"hello".to_vec()]);
        assert_eq!(s.next_seq, Some(1005));
    }

    #[test]
    fn in_order_packets_emit_each() {
        let mut s = ReassemblyDirState::default();
        
        feed(&mut s, &cfg(), 1000, b"abc");
        
        let out = feed(&mut s, &cfg(), 1003, b"def");
        
        assert_eq!(out, vec![b"def".to_vec()]);
    }

    #[test]
    fn out_of_order_held_then_drained() {
        let mut s = ReassemblyDirState::default();
        feed(&mut s, &cfg(), 1000, b"abc");
        
        // Pakiet "ghi" przybywa przed "def".
        let out1 = feed(&mut s, &cfg(), 1006, b"ghi");
        assert!(out1.is_empty());
        
        let out2 = feed(&mut s, &cfg(), 1003, b"def");
        // Najpierw def, potem podpięte ghi z out_of_order.
        
        assert_eq!(out2, vec![b"def".to_vec(), b"ghi".to_vec()]);
        assert_eq!(s.next_seq, Some(1009));
    }

    #[test]
    fn pure_retransmit_dropped() {
        let mut s = ReassemblyDirState::default();
        
        feed(&mut s, &cfg(), 1000, b"abc");
        
        let out = feed(&mut s, &cfg(), 1000, b"abc");
        
        assert!(out.is_empty());
    }

    #[test]
    fn partial_overlap_left_takes_tail() {
        let mut s = ReassemblyDirState::default();
        
        feed(&mut s, &cfg(), 1000, b"abc");
        
        // "bcd" — 'b','c' to retransmit, 'd' nowe.
        let out = feed(&mut s, &cfg(), 1001, b"bcd");
        
        assert_eq!(out, vec![b"d".to_vec()]);
        assert_eq!(s.next_seq, Some(1004));
    }

    #[test]
    fn wraparound_in_order() {
        let mut s = ReassemblyDirState::default();
        
        feed(&mut s, &cfg(), u32::MAX - 2, b"ab"); // emits, next = u32::MAX
        
        let out = feed(&mut s, &cfg(), u32::MAX, b"cd"); // wrap to 1
        
        assert_eq!(out, vec![b"cd".to_vec()]);
        assert_eq!(s.next_seq, Some(1));
    }

    #[test]
    fn limit_drops_out_of_order_segment() {
        let mut c = cfg();
        c.max_buffered_bytes = 8;
        
        let mut s = ReassemblyDirState::default();
        
        feed(&mut s, &c, 1000, b"abcd"); // baseline
        feed(&mut s, &c, 1100, &[0xaa; 4]);
        feed(&mut s, &c, 1200, &[0xbb; 4]);
        
        // Trzeci ooo segment — limit przekroczony, drop.
        let out = feed(&mut s, &c, 1300, &[0xcc; 4]);
        
        assert!(out.is_empty());
        assert_eq!(s.buffered, 8);
    }
}