use std::sync::Arc;
use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime};

use etherparse::PacketBuilder;

use ngfw::data_plane::ips::config::{
    IpsAction, IpsAppProtocol, IpsConfig, IpsDetectionConfig, IpsGeneralConfig, IpsMatchType,
    IpsPatternEncoding, IpsSeverity, IpsSignatureConfig,
};

use ngfw::data_plane::ips::ips::Ips;
use ngfw::dpi::{AppProto, DpiContext};
use ngfw::data_plane::packet_context::PacketContext;

const ITERS: usize = 500_000;
const TARGET_NS: u128 = 1_000;

fn main() {
    let ips = Ips::new(config()).expect("ips should initialize");

    let no_match = build_tcp_packet(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", 80);
    let first_match = build_tcp_packet(b"admin:admin", 23);
    let last_match = build_tcp_packet(b"\xfc\x48\x83\xe4\xf0", 4444);

    let no_match_ns = run_case("no_match", &ips, &no_match);
    let first_match_ns = run_case("first_match", &ips, &first_match);
    let last_match_ns = run_case("last_match", &ips, &last_match);

    assert!(no_match_ns < TARGET_NS, "no_match IPS literal AC path >= 1us");
    assert!(first_match_ns < TARGET_NS, "first_match IPS literal AC path >= 1us");
    assert!(last_match_ns < TARGET_NS, "last_match IPS literal AC path >= 1us");
}

fn run_case(name: &str, ips: &Ips, ctx: &PacketContext) -> u128 {
    for _ in 0..10_000 {
        black_box(ips.inspect_packet(black_box(ctx)));
    }

    let started = Instant::now();
    for _ in 0..ITERS {
        black_box(ips.inspect_packet(black_box(ctx)));
    }
    let elapsed = started.elapsed();
    let ns = nanos_per_iter(elapsed, ITERS);

    println!("{name}: {ns} ns/packet");

    ns
}

fn nanos_per_iter(elapsed: Duration, iters: usize) -> u128 {
    elapsed.as_nanos() / iters as u128
}

fn text_signature(
    id: &str,
    name: &str,
    category: &str,
    pattern: &str,
    severity: IpsSeverity,
    action: IpsAction,
    app_protocols: Vec<IpsAppProtocol>,
    dst_ports: Vec<u16>,
) -> IpsSignatureConfig {
    IpsSignatureConfig {
        id: id.into(),
        name: name.into(),
        enabled: true,
        category: category.into(),
        pattern: pattern.into(),
        match_type: IpsMatchType::Literal,
        pattern_encoding: IpsPatternEncoding::Text,
        case_insensitive: true,
        severity,
        action,
        app_protocols,
        src_ports: vec![],
        dst_ports,
    }
}

fn hex_signature(
    id: &str,
    name: &str,
    pattern: &str,
    severity: IpsSeverity,
    action: IpsAction,
) -> IpsSignatureConfig {
    IpsSignatureConfig {
        id: id.into(),
        name: name.into(),
        enabled: true,
        category: "shellcode".into(),
        pattern: pattern.into(),
        match_type: IpsMatchType::Literal,
        pattern_encoding: IpsPatternEncoding::Hex,
        case_insensitive: false,
        severity,
        action,
        app_protocols: vec![],
        src_ports: vec![],
        dst_ports: vec![],
    }
}

fn config() -> IpsConfig {
    IpsConfig {
        general: IpsGeneralConfig { enabled: true },
        detection: IpsDetectionConfig {
            enabled: true,
            max_payload_bytes: 4096,
            max_matches_per_packet: 10,
        },
        signatures: vec![
            text_signature(
                "mirai-telnet-admin-admin",
                "Mirai default telnet credentials admin/admin",
                "mirai",
                "admin:admin",
                IpsSeverity::Critical,
                IpsAction::Alert,
                vec![],
                vec![23, 2323],
            ),
            text_signature(
                "mirai-telnet-root-xmhdipc",
                "Mirai default telnet credentials root/xmhdipc",
                "mirai",
                "root:xmhdipc",
                IpsSeverity::Critical,
                IpsAction::Alert,
                vec![],
                vec![23, 2323],
            ),
            text_signature(
                "mirai-http-hnap-scan",
                "Mirai HNAP HTTP scan",
                "mirai",
                "/HNAP1/",
                IpsSeverity::High,
                IpsAction::Alert,
                vec![IpsAppProtocol::Http],
                vec![80, 8080],
            ),
            text_signature(
                "sqli-union-select",
                "SQL injection UNION SELECT",
                "sqli",
                "UNION SELECT",
                IpsSeverity::High,
                IpsAction::Block,
                vec![IpsAppProtocol::Http],
                vec![80, 8080],
            ),
            text_signature(
                "sqli-or-1-eq-1",
                "SQL injection OR 1=1",
                "sqli",
                "OR 1=1",
                IpsSeverity::High,
                IpsAction::Block,
                vec![IpsAppProtocol::Http],
                vec![80, 8080],
            ),
            text_signature(
                "sqli-sleep-function",
                "SQL injection SLEEP function",
                "sqli",
                "SLEEP(",
                IpsSeverity::Medium,
                IpsAction::Alert,
                vec![IpsAppProtocol::Http],
                vec![80, 8080],
            ),
            hex_signature(
                "shellcode-x86-nop-sled",
                "x86 shellcode NOP sled",
                "90909090",
                IpsSeverity::High,
                IpsAction::Alert,
            ),
            hex_signature(
                "shellcode-bin-sh",
                "Unix shell path /bin/sh",
                "2f62696e2f7368",
                IpsSeverity::Critical,
                IpsAction::Block,
            ),
            hex_signature(
                "shellcode-x86-execve-bin-sh",
                "x86 execve /bin/sh shellcode fragment",
                "31c050682f2f7368",
                IpsSeverity::Critical,
                IpsAction::Block,
            ),
            hex_signature(
                "shellcode-x64-stack-align",
                "x64 shellcode stack alignment prologue",
                "fc4883e4f0",
                IpsSeverity::High,
                IpsAction::Alert,
            ),
        ],
    }
}

fn build_tcp_packet(payload: &[u8], dst_port: u16) -> PacketContext {
    let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(12345, dst_port, 1, 1024);

    let mut raw = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut raw, payload).expect("packet should serialize");

    PacketContext::from_raw_full(
        raw,
        Arc::<str>::from("eth1"),
        Vec::new(),
        SystemTime::now(),
        Some(DpiContext {
            app_proto: Some(AppProto::Http),
            ..Default::default()
        }),
        None,
    )
    .expect("packet context should parse")
}
