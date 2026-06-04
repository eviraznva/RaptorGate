use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;

use etherparse::PacketBuilder;
use ngfw::dpi::DpiClassifier;

use raptorgate_pcap::features::{build_features, BuildOptions};
use raptorgate_pcap::index::MappedPcap;
use raptorgate_pcap::labels::{LabelIndex, LabelRow};
use raptorgate_pcap::output::FeatureOutput;

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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    tmp.push(format!("raptorgate_pcap_e2e_{}_{}.pcap", std::process::id(), nanos));
    std::fs::File::create(&tmp).unwrap().write_all(&buf).unwrap();
    tmp
}

fn http_get_request_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 7, 8, 9, 10, 11])
        .ipv4(src, dst, 64)
        .tcp(sport, dport, 1000, 0);
    let size = builder.size(payload.len());
    let mut out = Vec::with_capacity(size);
    builder.write(&mut out, payload).unwrap();
    out
}

fn build_label_index_with_row(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, proto: u8) -> LabelIndex {
    let mut idx = LabelIndex::new();
    idx.insert_row(LabelRow {
        src_ip: IpAddr::V4(src.into()),
        dst_ip: IpAddr::V4(dst.into()),
        src_port: sp,
        dst_port: dp,
        proto,
        raw_label: "DDoS",
        raw_attack_label: Some("DDoS"),
        timestamp: Some(100.0),
        flow_duration_us: Some(60_000_000),
    });
    idx
}

#[test]
fn build_features_emits_one_row_per_packet() {
    let frames = vec![
        (1, 0, http_get_request_frame([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80)),
        (2, 0, http_get_request_frame([10, 0, 0, 1], [10, 0, 0, 2], 12346, 80)),
        (3, 0, http_get_request_frame([10, 0, 0, 3], [10, 0, 0, 4], 33333, 80)),
    ];
    let path = write_pcap(&frames);

    let mapped = MappedPcap::open(&path).unwrap();
    let labels = build_label_index_with_row([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 6);
    let classifier = Arc::new(DpiClassifier::new());

    let out: FeatureOutput = build_features(
        &mapped,
        &labels,
        classifier,
        BuildOptions {
            num_workers: Some(2),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(out.n_rows, 3);
    assert_eq!(out.features.len(), 3 * 38);
    assert_eq!(out.label.len(), 3);
    assert_eq!(out.attack_idx.len(), 3);
    assert_eq!(out.matched.len(), 3);
    assert_eq!(out.flow_id.len(), 3);

    let row1 = &out.features[0..38];
    let row3 = &out.features[76..114];
    assert!(row1[5] >= 0.0);
    assert_ne!(row1, row3);

    std::fs::remove_file(&path).ok();
}

#[test]
fn build_features_matches_label_for_known_flow() {
    let frames = vec![(
        100,
        0,
        http_get_request_frame([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80),
    )];
    let path = write_pcap(&frames);

    let mapped = MappedPcap::open(&path).unwrap();
    let labels = build_label_index_with_row([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 6);
    let classifier = Arc::new(DpiClassifier::new());

    let out = build_features(
        &mapped,
        &labels,
        classifier,
        BuildOptions {
            num_workers: Some(1),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(out.n_rows, 1);
    assert_eq!(out.label[0], 1);
    assert!(out.matched[0]);
    assert_eq!(out.attack_idx[0], 1);

    std::fs::remove_file(&path).ok();
}

fn dns_response_frame(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    rcode: u16,
) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&0x1234u16.to_be_bytes());
    let rcode_byte = (rcode & 0x0f) as u8;
    let byte0 = 0x81u8;
    let byte1 = 0x80u8 | rcode_byte;
    dns.extend_from_slice(&[byte0, byte1]);
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&0u16.to_be_bytes());
    dns.extend_from_slice(&0u16.to_be_bytes());
    dns.extend_from_slice(&0u16.to_be_bytes());
    dns.extend_from_slice(b"\x07example\x03com\x00");
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());

    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 7, 8, 9, 10, 11])
        .ipv4(src, dst, 64)
        .udp(sport, dport);
    let size = builder.size(dns.len());
    let mut out = Vec::with_capacity(size);
    builder.write(&mut out, &dns).unwrap();
    out
}

const NXDOMAIN_RATIO_IDX: usize = 36;

fn nxdomain_row(row: &[f32]) -> f32 {
    row[NXDOMAIN_RATIO_IDX]
}

#[test]
fn dns_rcode_populates_nxdomain_ratio() {
    let frames = vec![
        (
            1,
            0,
            dns_response_frame([10, 0, 0, 1], [10, 0, 0, 2], 53, 33333, 3),
        ),
        (
            2,
            0,
            dns_response_frame([10, 0, 0, 1], [10, 0, 0, 2], 53, 33334, 3),
        ),
    ];
    let path = write_pcap(&frames);

    let mapped = MappedPcap::open(&path).unwrap();
    let labels = LabelIndex::new();
    let classifier = Arc::new(DpiClassifier::new());

    let out = build_features(
        &mapped,
        &labels,
        classifier,
        BuildOptions {
            num_workers: Some(1),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(out.n_rows, 2);
    let r0 = nxdomain_row(&out.features[0..38]);
    let r1 = nxdomain_row(&out.features[38..76]);
    assert!(
        r0 < r1,
        "expected nxdomain_ratio to accumulate after a NXDOMAIN response; got {r0} then {r1}"
    );
    assert!(r1 > 0.0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn split_http_request_reassembles_into_http() {
    let full = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    let split_at = "GET / HTTP/1.1\r\n".len();
    let part1 = &full[..split_at];
    let part2 = &full[split_at..];

    let frames = vec![
        (
            1,
            0,
            http_get_request_frame_split([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, part1),
        ),
        (
            2,
            0,
            http_get_request_frame_split([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, part2),
        ),
    ];
    let path = write_pcap(&frames);

    let mapped = MappedPcap::open(&path).unwrap();
    let labels = LabelIndex::new();
    let classifier = Arc::new(DpiClassifier::new());

    let out = build_features(
        &mapped,
        &labels,
        classifier,
        BuildOptions {
            num_workers: Some(1),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(out.n_rows, 2);
    let row0_host_entropy = out.features[21];
    let row1_host_entropy = out.features[21 + 38];
    assert_eq!(row0_host_entropy, 0.0, "row 0 expected no Host (partial request)");
    assert!(row1_host_entropy > 0.0, "row 1 expected Host entropy > 0");

    std::fs::remove_file(&path).ok();
}

fn http_get_request_frame_split(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 7, 8, 9, 10, 11])
        .ipv4(src, dst, 64)
        .tcp(sport, dport, 1000, 0);
    let size = builder.size(payload.len());
    let mut out = Vec::with_capacity(size);
    builder.write(&mut out, payload).unwrap();
    out
}
