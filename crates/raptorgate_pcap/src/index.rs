use std::collections::HashMap;
use std::fs::File;
use std::net::IpAddr;

use etherparse::{SlicedPacket, TransportSlice};
use memmap2::{Advice, Mmap};
use pcap_file::pcap::PcapParser;
use pcap_file::pcapng::blocks::Block;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::PcapNgParser;
use pcap_file::DataLink;

use crate::error::{PcapError, Result};

#[derive(Debug, Clone, Copy)]
pub struct PacketRef {
    pub ts: f64,
    pub offset: u64,
    pub length: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct IndexedPacket {
    pub ts: f64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_proto: u8,
    pub ip_version: u8,
    pub ttl: u8,
    pub tcp_flags: Option<u8>,
    pub tcp_window: Option<u16>,
    pub frame_offset: u64,
    pub frame_length: u32,
    pub payload_offset: u32,
    pub payload_length: u32,
}

#[derive(Debug, Default)]
pub struct PcapIndex {
    pub by_src: HashMap<IpAddr, Vec<IndexedPacket>>,
    pub record_count: u64,
    pub unparsable: u64,
    pub linktype: u32,
}

impl PcapIndex {
    pub fn src_ips(&self) -> Vec<IpAddr> {
        self.by_src.keys().copied().collect()
    }

    pub fn partition(&self, n: usize) -> Vec<Vec<IpAddr>> {
        let mut keys: Vec<IpAddr> = self.by_src.keys().copied().collect();
        keys.sort_unstable();
        let n = n.max(1);
        let mut out: Vec<Vec<IpAddr>> = (0..n).map(|_| Vec::new()).collect();
        for (i, k) in keys.into_iter().enumerate() {
            out[i % n].push(k);
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PcapFormat {
    Pcap,
    PcapNg,
}

fn detect_format(mmap: &[u8]) -> Result<PcapFormat> {
    if mmap.len() < 4 {
        return Err(PcapError::PcapParse("file smaller than 4 bytes".into()));
    }
    let magic = u32::from_le_bytes([mmap[0], mmap[1], mmap[2], mmap[3]]);
    match magic {
        0xa1b2c3d4 | 0xd4c3b2a1 => Ok(PcapFormat::Pcap),
        0x0a0d0d0a => Ok(PcapFormat::PcapNg),
        _ => Err(PcapError::PcapParse(format!(
            "PcapHeader: wrong magic number {:#x}",
            magic
        ))),
    }
}

pub struct MappedPcap {
    mmap: Mmap,
    linktype: u32,
}

impl MappedPcap {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let file = File::open(path.as_ref()).map_err(PcapError::PcapOpen)?;
        let mmap = unsafe { Mmap::map(&file) }.map_err(PcapError::Mmap)?;
        let linktype = linktype_of(&mmap)?;
        let _ = hint_kernel(&mmap);
        Ok(Self { mmap, linktype })
    }

    pub fn mmap(&self) -> &[u8] {
        &self.mmap
    }

    pub fn linktype(&self) -> u32 {
        self.linktype
    }
}

fn hint_kernel(mmap: &Mmap) -> std::io::Result<()> {
    let _ = mmap.advise(Advice::WillNeed);
    let _ = mmap.advise(Advice::Sequential);
    mmap.lock()
}

fn linktype_of(mmap: &[u8]) -> Result<u32> {
    match detect_format(mmap)? {
        PcapFormat::Pcap => {
            let (_, parser) =
                PcapParser::new(mmap).map_err(|e| PcapError::PcapParse(e.to_string()))?;
            Ok(datalink_to_u32(parser.header().datalink))
        }
        PcapFormat::PcapNg => {
            let (mut src, mut parser) =
                PcapNgParser::new(mmap).map_err(|e| PcapError::PcapParse(e.to_string()))?;
            while parser.interfaces().is_empty() {
                match parser.next_block(src) {
                    Ok((rem, _)) => src = rem,
                    Err(pcap_file::PcapError::IncompleteBuffer) => {
                        return Err(PcapError::PcapParse(
                            "pcapng: no interface description block found".into(),
                        ));
                    }
                    Err(e) => return Err(PcapError::PcapParse(e.to_string())),
                }
            }
            Ok(datalink_to_u32(
                parser.interfaces()[0].linktype,
            ))
        }
    }
}

fn datalink_to_u32(d: DataLink) -> u32 {
    match d {
        DataLink::ETHERNET => 1,
        DataLink::LINUX_SLL => 113,
        DataLink::RAW => 12,
        DataLink::IPV4 => 228,
        DataLink::IPV6 => 229,
        _ => u32::from(d),
    }
}

pub fn prepass(mapped: &MappedPcap) -> Result<PcapIndex> {
    let mmap = mapped.mmap();
    match detect_format(mmap)? {
        PcapFormat::Pcap => prepass_pcap(mmap, mapped.linktype()),
        PcapFormat::PcapNg => prepass_pcapng(mmap, mapped.linktype()),
    }
}

fn prepass_pcap(mmap: &[u8], linktype: u32) -> Result<PcapIndex> {
    let (mut src, parser) =
        PcapParser::new(mmap).map_err(|e| PcapError::PcapParse(e.to_string()))?;
    let mut index = PcapIndex {
        linktype,
        ..PcapIndex::default()
    };
    let mmap_base = mmap.as_ptr();

    loop {
        match parser.next_packet(src) {
            Ok((rem, pkt)) => {
                let ts = pkt.timestamp.as_secs() as f64
                    + pkt.timestamp.subsec_micros() as f64 / 1_000_000.0;

                if let Some(indexed) = index_packet(linktype, mmap_base, &pkt.data, ts) {
                    index.by_src.entry(indexed.src_ip).or_default().push(indexed);
                } else {
                    index.unparsable += 1;
                }
                index.record_count += 1;

                if rem.is_empty() {
                    break;
                }
                src = rem;
            }
            Err(pcap_file::PcapError::IncompleteBuffer) => break,
            Err(_) => {
                index.unparsable += 1;
                break;
            }
        }
    }

    Ok(index)
}

fn prepass_pcapng(mmap: &[u8], linktype: u32) -> Result<PcapIndex> {
    let (mut src, mut parser) = PcapNgParser::new(mmap)
        .map_err(|e| PcapError::PcapParse(e.to_string()))?;
    let mut index = PcapIndex {
        linktype,
        ..Default::default()
    };
    let mmap_base = mmap.as_ptr();

    loop {
        match parser.next_block(src) {
            Ok((rem, block)) => {
                match block {
                    Block::EnhancedPacket(epb) => {
                        let res = parser
                            .packet_interface(&epb)
                            .and_then(|idb| {
                                idb.options.iter().find_map(|opt| {
                                    if let InterfaceDescriptionOption::IfTsResol(r) = opt {
                                        Some(*r)
                                    } else {
                                        None
                                    }
                                })
                            })
                            .unwrap_or(6);
                        let (mult, denom) = pcapng_ts_scale(res);
                        let ts = (epb.timestamp.as_secs() as f64 * mult)
                            + (epb.timestamp.subsec_nanos() as f64 * mult / denom);
                        if let Some(indexed) =
                            index_packet(linktype, mmap_base, &epb.data, ts)
                        {
                            index.by_src.entry(indexed.src_ip).or_default().push(indexed);
                        } else {
                            index.unparsable += 1;
                        }
                        index.record_count += 1;
                    }
                    Block::SimplePacket(spb) => {
                        if let Some(indexed) =
                            index_packet(linktype, mmap_base, &spb.data, 0.0)
                        {
                            index.by_src.entry(indexed.src_ip).or_default().push(indexed);
                        } else {
                            index.unparsable += 1;
                        }
                        index.record_count += 1;
                    }
                    _ => {}
                }
                if rem.is_empty() {
                    break;
                }
                src = rem;
            }
            Err(pcap_file::PcapError::IncompleteBuffer) => break,
            Err(_) => {
                index.unparsable += 1;
                break;
            }
        }
    }

    Ok(index)
}

fn pcapng_ts_scale(res: u8) -> (f64, f64) {
    match res {
        6 => (1_000.0, 1_000_000_000.0),
        9 => (1.0, 1_000_000_000.0),
        3 => (1_000_000.0, 1_000_000_000.0),
        0..=6 => (10f64.powi((6 - res) as i32), 1_000_000_000.0),
        _ => (1.0, 1_000_000_000.0),
    }
}

pub fn src_ip_from_data(linktype: u32, data: &[u8]) -> Option<IpAddr> {
    let sliced = match linktype {
        1 => SlicedPacket::from_ethernet(data).ok()?,
        113 => SlicedPacket::from_linux_sll(data).ok()?,
        101 | 12 => SlicedPacket::from_ip(data).ok()?,
        _ => return None,
    };
    match sliced.net? {
        etherparse::NetSlice::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.header().source_addr())),
        etherparse::NetSlice::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.header().source_addr())),
        etherparse::NetSlice::Arp(_) => None,
    }
}

fn index_packet(
    linktype: u32,
    mmap_base: *const u8,
    data: &[u8],
    ts: f64,
) -> Option<IndexedPacket> {
    let sliced = match linktype {
        1 => SlicedPacket::from_ethernet(data).ok()?,
        113 => SlicedPacket::from_linux_sll(data).ok()?,
        101 | 12 | 228 | 229 => SlicedPacket::from_ip(data).ok()?,
        _ => return None,
    };
    let net = sliced.net.as_ref()?;
    let (ip_version, ip_proto, ttl, src_ip, dst_ip) = match net {
        etherparse::NetSlice::Ipv4(v4) => {
            let h = v4.header();
            (4u8, h.protocol().0, h.ttl(), IpAddr::V4(h.source_addr()), IpAddr::V4(h.destination_addr()))
        }
        etherparse::NetSlice::Ipv6(v6) => {
            let h = v6.header();
            (6u8, h.next_header().0, h.hop_limit(), IpAddr::V6(h.source_addr()), IpAddr::V6(h.destination_addr()))
        }
        etherparse::NetSlice::Arp(_) => return None,
    };

    let (src_port, dst_port, tcp_flags, tcp_window, payload_offset, payload_length) =
        match sliced.transport.as_ref() {
            Some(TransportSlice::Tcp(t)) => {
                let mut flags = 0u8;
                if t.syn() { flags |= 0x02; }
                if t.ack() { flags |= 0x10; }
                if t.fin() { flags |= 0x01; }
                if t.rst() { flags |= 0x04; }
                if t.psh() { flags |= 0x08; }
                if t.urg() { flags |= 0x20; }
                if t.ece() { flags |= 0x40; }
                if t.cwr() { flags |= 0x80; }
                let payload = t.payload();
                let po = if payload.is_empty() {
                    0u32
                } else {
                    (payload.as_ptr() as usize).saturating_sub(mmap_base as usize) as u32
                };
                (t.source_port(), t.destination_port(), Some(flags), Some(t.window_size()), po, payload.len() as u32)
            }
            Some(TransportSlice::Udp(u)) => {
                let payload = u.payload();
                let po = if payload.is_empty() {
                    0u32
                } else {
                    (payload.as_ptr() as usize).saturating_sub(mmap_base as usize) as u32
                };
                (u.source_port(), u.destination_port(), None, None, po, payload.len() as u32)
            }
            _ => (0u16, 0u16, None, None, 0u32, 0u32),
        };

    let frame_offset = (data.as_ptr() as usize).saturating_sub(mmap_base as usize) as u64;

    Some(IndexedPacket {
        ts,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ip_proto,
        ip_version,
        ttl,
        tcp_flags,
        tcp_window,
        frame_offset,
        frame_length: data.len() as u32,
        payload_offset,
        payload_length,
    })
}

pub fn packet_bytes<'a>(mapped: &'a MappedPcap, r: &PacketRef) -> Option<&'a [u8]> {
    let start = r.offset as usize;
    let end = start.checked_add(r.length as usize)?;
    if end > mapped.mmap().len() {
        return None;
    }
    Some(&mapped.mmap()[start..end])
}

pub fn frame_bytes<'a>(mapped: &'a MappedPcap, p: &IndexedPacket) -> Option<&'a [u8]> {
    let start = p.frame_offset as usize;
    let end = start.checked_add(p.frame_length as usize)?;
    if end > mapped.mmap().len() {
        return None;
    }
    Some(&mapped.mmap()[start..end])
}

pub fn payload_bytes<'a>(mapped: &'a MappedPcap, p: &IndexedPacket) -> &'a [u8] {
    let start = p.payload_offset as usize;
    let end = start.saturating_add(p.payload_length as usize);
    if end > mapped.mmap().len() || start > mapped.mmap().len() {
        return &[];
    }
    &mapped.mmap()[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::io::Write;

    fn write_pcap(frames: &[(u32, u32, Vec<u8>)]) -> std::path::PathBuf {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&65535u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());

        for (ts_sec, ts_usec, frame) in frames {
            buf.extend_from_slice(&ts_sec.to_le_bytes());
            buf.extend_from_slice(&ts_usec.to_le_bytes());
            buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            buf.extend_from_slice(frame);
        }

        let mut tmp = std::env::temp_dir();
        tmp.push(format!(
            "raptorgate_pcap_index_{}_{}.pcap",
            std::process::id(),
            rand_u64()
        ));
        std::fs::File::create(&tmp).unwrap().write_all(&buf).unwrap();
        tmp
    }

    fn rand_u64() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            ^ (std::process::id() as u64).wrapping_mul(2654435761)
    }

    fn ipv4_tcp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 7, 8, 9, 10, 11])
            .ipv4(src, dst, 64)
            .tcp(sport, dport, 1000, 0);
        let size = builder.size(0);
        let mut out = Vec::with_capacity(size);
        builder.write(&mut out, &[]).unwrap();
        out
    }

    #[test]
    fn prepass_partitions_by_src_ip() {
        let frames = vec![
            (1, 0, ipv4_tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 12345, 443)),
            (2, 0, ipv4_tcp_frame([10, 0, 0, 1], [10, 0, 0, 3], 12346, 80)),
            (3, 0, ipv4_tcp_frame([10, 0, 0, 2], [10, 0, 0, 1], 443, 12345)),
        ];
        let path = write_pcap(&frames);

        let mapped = MappedPcap::open(&path).unwrap();
        assert_eq!(mapped.linktype(), 1);

        let idx = prepass(&mapped).unwrap();
        assert_eq!(idx.record_count, 3);
        assert_eq!(idx.unparsable, 0);
        assert_eq!(idx.by_src.len(), 2);

        let src1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let src2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(idx.by_src[&src1].len(), 2);
        assert_eq!(idx.by_src[&src2].len(), 1);

        for refs in idx.by_src.values() {
            for p in refs {
                let bytes = frame_bytes(&mapped, p).unwrap();
                assert!(!bytes.is_empty());
                assert!(crate::parse::parse_ethernet(p.ts, bytes).is_some());
                let payload = payload_bytes(&mapped, p);
                assert!(p.payload_offset as usize <= bytes.len());
                assert!(p.payload_offset as usize + payload.len() <= bytes.len());
            }
        }

        let buckets = idx.partition(2);
        let total: usize = buckets.iter().map(|b| b.len()).sum();
        assert_eq!(total, 2);
        for b in &buckets {
            for ip in b {
                assert!(idx.by_src.contains_key(ip));
            }
        }

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn prepass_preserves_timestamps() {
        let frames = vec![
            (100, 500_000, ipv4_tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 1, 2)),
            (200, 0, ipv4_tcp_frame([10, 0, 0, 3], [10, 0, 0, 4], 3, 4)),
        ];
        let path = write_pcap(&frames);
        let mapped = MappedPcap::open(&path).unwrap();
        let idx = prepass(&mapped).unwrap();

        let all_refs: Vec<_> = idx.by_src.values().flatten().collect();
        let mut by_ts: Vec<f64> = all_refs.iter().map(|r| r.ts).collect();
        by_ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert!((by_ts[0] - 100.5).abs() < 1e-6);
        assert!((by_ts[1] - 200.0).abs() < 1e-6);

        std::fs::remove_file(&path).ok();
    }
}
