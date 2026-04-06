//! Silnik defragmentacji IPv4.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use etherparse::{Ipv4Header, Ipv4HeaderSlice, NetSlice, SlicedPacket};

use crate::data_plane::interface_sniffer::RawPacket;
use crate::data_plane::packet_context::PacketContext;

// Limity i czasy życia używane przez silnik (ochrona przed DoS).
pub struct DefragConfig {
    pub fragment_timeout: Duration,
    pub max_datagrams: usize,
    pub max_fragments_per_datagram: usize,
    pub max_payload_bytes: usize,
}

impl Default for DefragConfig {
    fn default() -> Self {
        DefragConfig {
            fragment_timeout: Duration::from_secs(30),
            max_datagrams: 1024,
            max_fragments_per_datagram: 64,
            max_payload_bytes: 65535,
        }
    }
}

// Klucz identyfikujący strumień składania jednego datagramu.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FragKey {
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    identification: u16,
}

// Stan składania jednego datagramu IPv4.
struct ReassemblyEntry {
    fragments: BTreeMap<u16, Vec<u8>>,
    total_payload_len: Option<u16>,
    first_header: Option<Ipv4Header>,
    created_at: Instant,
    fragment_count: usize,
    anomalies: Vec<String>,
}

impl ReassemblyEntry {
    fn new() -> Self {
        ReassemblyEntry {
            fragments: BTreeMap::new(),
            total_payload_len: None,
            first_header: None,
            created_at: Instant::now(),
            fragment_count: 0,
            anomalies: Vec::new(),
        }
    }

    // Zwraca true gdy wszystkie bajty od 0 do total_payload_len są pokryte.
    fn is_complete(&self) -> bool {
        let Some(total) = self.total_payload_len else {
            return false;
        };
        if self.first_header.is_none() {
            return false;
        }
        let mut covered_up_to: u16 = 0;
        for (&start, payload) in &self.fragments {
            if start > covered_up_to {
                return false;
            }
            let end = start.saturating_add(payload.len() as u16);
            if end > covered_up_to {
                covered_up_to = end;
            }
        }
        covered_up_to >= total
    }

    // Zwraca true gdy zakres [new_start, new_end) nakłada się na istniejący fragment.
    fn has_overlap(&self, new_start: u16, new_end: u16) -> bool {
        for (&start, payload) in &self.fragments {
            let end = start.saturating_add(payload.len() as u16);
            if start < new_end && new_start < end {
                return true;
            }
        }
        false
    }

    // Składa fragmenty w ciągły bufor payloadu.
    fn assemble_payload(&self) -> Vec<u8> {
        let total = self.total_payload_len.unwrap_or(0) as usize;
        let mut buf = vec![0u8; total];
        for (&start, payload) in &self.fragments {
            let s = start as usize;
            let e = (s + payload.len()).min(total);
            buf[s..e].copy_from_slice(&payload[..e - s]);
        }
        buf
    }
}

// Wynik przetworzenia fragmentu przez silnik.
pub enum DefragResult {
    Pending,
    Complete(Vec<u8>),
    CompleteWithAnomaly(Vec<u8>, Vec<String>),
    Dropped(&'static str),
}

// Silnik defragmentacji współdzielony między wątkami przez Arc.
pub struct IpDefragEngine {
    state: Mutex<EngineState>,
    config: DefragConfig,
}

struct EngineState {
    entries: HashMap<FragKey, ReassemblyEntry>,
}

impl IpDefragEngine {
    pub fn new(config: DefragConfig) -> Self {
        IpDefragEngine {
            state: Mutex::new(EngineState {
                entries: HashMap::new(),
            }),
            config,
        }
    }

    /// Takes a raw captured packet, reassembles it if fragmented, and returns
    /// a fully parsed `PacketContext` once a complete packet is available.
    /// Returns `None` if the packet is a pending fragment or was dropped.
    pub fn process_raw(&self, packet: RawPacket) -> Option<PacketContext> {
        let RawPacket { raw, iface } = packet;

        let sliced = match SlicedPacket::from_ethernet(&raw) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("failed to parse captured packet: {e}");
                return None;
            }
        };

        if !sliced.is_ip_payload_fragmented() {
            drop(sliced);
            return PacketContext::from_raw(raw, iface).ok();
        }

        let result = self.process(&sliced);
        drop(sliced);

        match result {
            DefragResult::Pending => None,
            DefragResult::Dropped(reason) => {
                tracing::debug!("defrag dropped packet: {reason}");
                None
            }
            DefragResult::Complete(eth_frame) => PacketContext::from_raw(eth_frame, iface).ok(),
            DefragResult::CompleteWithAnomaly(eth_frame, anomalies) => {
                let mut ctx = PacketContext::from_raw(eth_frame, iface).ok()?;
                ctx.with_warnings_mut(|warnings| warnings.extend(anomalies));
                Some(ctx)
            }
        }
    }

    // Przetwarza jeden fragment IPv4. Wywołuj tylko gdy packet.is_ip_payload_fragmented() == true.
    pub(crate) fn process(&self, packet: &SlicedPacket) -> DefragResult {
        let ipv4 = match &packet.net {
            Some(NetSlice::Ipv4(v4)) => v4,
            _ => return DefragResult::Dropped("non-IPv4 fragment passed to defrag engine"),
        };

        let header_slice: Ipv4HeaderSlice = ipv4.header();
        let fragment_offset_bytes: u16 = header_slice.fragments_offset().byte_offset();
        let more_fragments: bool = header_slice.more_fragments();
        let payload: &[u8] = ipv4.payload().payload;

        // RFC 791 wymaga wyrównania do 8 bajtów dla fragmentów pośrednich.
        // Zamiast odrzucać, rejestrujemy anomalię i próbujemy złożyć.
        let alignment_anomaly = if more_fragments && payload.len() % 8 != 0 {
            Some(format!(
                "unaligned intermediate fragment: offset={fragment_offset_bytes} payload_len={} (not a multiple of 8)",
                payload.len()
            ))
        } else {
            None
        };

        let new_end = match fragment_offset_bytes.checked_add(payload.len() as u16) {
            Some(e) => e,
            None => return DefragResult::Dropped("fragment offset + length overflows u16"),
        };

        if new_end as usize > self.config.max_payload_bytes {
            return DefragResult::Dropped("reassembled payload would exceed max_payload_bytes");
        }

        let key = FragKey {
            src: header_slice.source(),
            dst: header_slice.destination(),
            protocol: header_slice.protocol().0,
            identification: header_slice.identification(),
        };

        let mut state = self.state.lock().unwrap();

        // Usunięcie przeterminowanych wpisów.
        let timeout = self.config.fragment_timeout;
        state
            .entries
            .retain(|_, e| e.created_at.elapsed() < timeout);

        if !state.entries.contains_key(&key) && state.entries.len() >= self.config.max_datagrams {
            return DefragResult::Dropped("max concurrent datagrams limit reached");
        }

        let entry = state
            .entries
            .entry(key)
            .or_insert_with(ReassemblyEntry::new);

        entry.fragment_count += 1;
        if entry.fragment_count > self.config.max_fragments_per_datagram {
            return DefragResult::Dropped("max fragments per datagram exceeded");
        }

        // Nakładające się fragmenty są odrzucane zgodnie z RFC 3128 / RFC 5722.
        if entry.has_overlap(fragment_offset_bytes, new_end) {
            return DefragResult::Dropped("overlapping fragment detected (RFC 3128 / RFC 5722)");
        }

        if let Some(reason) = alignment_anomaly {
            eprintln!(
                "[defrag] ANOMALY (id={}): {reason}",
                header_slice.identification()
            );
            entry.anomalies.push(reason);
        }

        if fragment_offset_bytes == 0 {
            entry.first_header = Some(header_slice.to_header());
        }

        if !more_fragments {
            entry.total_payload_len = Some(new_end);
        }

        entry
            .fragments
            .insert(fragment_offset_bytes, payload.to_vec());

        if !entry.is_complete() {
            return DefragResult::Pending;
        }

        let payload_bytes = entry.assemble_payload();
        let mut ip_header = entry.first_header.clone().unwrap();
        let anomalies = std::mem::take(&mut entry.anomalies);

        let key_clone = FragKey {
            src: ip_header.source,
            dst: ip_header.destination,
            protocol: ip_header.protocol.0,
            identification: ip_header.identification,
        };
        state.entries.remove(&key_clone);
        drop(state);

        // Aktualizacja nagłówka IP: czyszczenie flag fragmentacji i przeliczenie sumy kontrolnej.
        ip_header.more_fragments = false;
        ip_header.dont_fragment = false;
        ip_header.fragment_offset = etherparse::IpFragOffset::ZERO;
        if ip_header.set_payload_len(payload_bytes.len()).is_err() {
            return DefragResult::Dropped(
                "reassembled payload too large for Ipv4Header::total_len",
            );
        }
        ip_header.header_checksum = ip_header.calc_header_checksum();

        let header_bytes = ip_header.to_bytes();
        let mut ip_packet = Vec::with_capacity(header_bytes.len() + payload_bytes.len());
        ip_packet.extend_from_slice(&header_bytes);
        ip_packet.extend_from_slice(&payload_bytes);

        // Pakiet IP owijamy w syntetyczną ramkę Ethernet (dummy MAC, EtherType 0x0800)
        // aby umożliwić ponowne parsowanie przez SlicedPacket::from_ethernet.
        let mut eth_frame = Vec::with_capacity(14 + ip_packet.len());
        eth_frame.extend_from_slice(&[0u8; 6]);
        eth_frame.extend_from_slice(&[0u8; 6]);
        eth_frame.extend_from_slice(&[0x08, 0x00]);
        eth_frame.extend_from_slice(&ip_packet);

        if anomalies.is_empty() {
            DefragResult::Complete(eth_frame)
        } else {
            DefragResult::CompleteWithAnomaly(eth_frame, anomalies)
        }
    }
}
