use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Linktype};
use raptorgate_testkit::{
    smoke_tcp_allow_warn_bundle, ProcessOutputWithPacketId, TestDaemon,
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let files: Vec<PathBuf> = if args.is_empty() {
        vec![
            "ssh_failed_handshake.pcapng".into(),
            "ssh_succesful_handshake.pcapng".into(),
        ]
    } else {
        args.into_iter().map(PathBuf::from).collect()
    };

    for path in &files {
        if !path.exists() {
            eprintln!("error: file not found: {}", path.display());
            continue;
        }
        if let Err(e) = replay_pcap_file(path).await {
            eprintln!("error replaying {}: {e}", path.display());
        }
    }

    Ok(())
}

async fn replay_pcap_file(path: &PathBuf) -> Result<()> {
    let mut cap = Capture::from_file(path)?;
    let linktype = cap.get_datalink();
    let file_name = path.file_name().unwrap().to_string_lossy().to_string();

    let daemon = TestDaemon::builder()
        .with_bundle(smoke_tcp_allow_warn_bundle())
        .build()
        .await?;

    let mut frame_idx = 0u64;
    while let Ok(packet) = cap.next_packet() {
        frame_idx += 1;

        let raw = match normalize_frame(packet.data, linktype) {
            Some(r) => r,
            None => {
                println!(
                    "[{file_name:20}] pkt#{frame_idx:5} SKIP  unsupported linktype"
                );
                continue;
            }
        };

        let iface = match infer_iface(&raw) {
            Some(i) => i,
            None => {
                println!(
                    "[{file_name:20}] pkt#{frame_idx:5} SKIP  non-IP/unroutable"
                );
                continue;
            }
        };

        let info = parse_addrs(&raw);
        let result = replay_one_packet(&daemon, raw, iface.clone()).await;

        let pid = result.packet_id.map(|id| id.0).unwrap_or(0);
        let outcome = match &result.output.stage_outcome {
            Some(o) => format!("{o:?}"),
            None => "None".into(),
        };
        let emitted = result.output.emitted.len();

        println!(
            "[{file_name:20}] pkt#{frame_idx:5} {iface:4} \
             pid={pid:<5} {src_ip}:{src_port} -> {dst_ip}:{dst_port} \
             outcome={outcome} emitted={emitted}",
            src_ip = info.src_ip,
            src_port = info.src_port,
            dst_ip = info.dst_ip,
            dst_port = info.dst_port,
        );
    }

    Ok(())
}

fn normalize_frame(data: &[u8], linktype: Linktype) -> Option<Vec<u8>> {
    match linktype {
        Linktype::ETHERNET => Some(data.to_vec()),
        Linktype::LINUX_SLL => {
            if data.len() < 16 {
                return None;
            }
            let protocol = u16::from_be_bytes([data[14], data[15]]);
            let addr_len = u16::from_be_bytes([data[4], data[5]]) as usize;
            let src_mac = if addr_len >= 6 {
                &data[6..12]
            } else {
                &[0u8; 6]
            };

            let mut eth = Vec::with_capacity(data.len() - 16 + 14);
            eth.extend_from_slice(&[0u8; 6]);
            eth.extend_from_slice(src_mac);
            eth.extend_from_slice(&protocol.to_be_bytes());
            eth.extend_from_slice(&data[16..]);
            Some(eth)
        }
        Linktype::LINUX_SLL2 => {
            if data.len() < 20 {
                return None;
            }
            let protocol = u16::from_be_bytes([data[0], data[1]]);
            let raw_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let addr_len = raw_len as usize;
            let src_mac = if addr_len >= 6 {
                &data[12..18]
            } else {
                &[0u8; 6]
            };

            let mut eth = Vec::with_capacity(data.len() - 20 + 14);
            eth.extend_from_slice(&[0u8; 6]);
            eth.extend_from_slice(src_mac);
            eth.extend_from_slice(&protocol.to_be_bytes());
            eth.extend_from_slice(&data[20..]);
            Some(eth)
        }
        _ => None,
    }
}

fn infer_iface(data: &[u8]) -> Option<Arc<str>> {
    let sliced = SlicedPacket::from_ethernet(data).ok()?;
    match sliced.net? {
        NetSlice::Ipv4(ip) => {
            let src = ip.header().source_addr();
            let o = src.octets();
            if o[0] == 192 && o[1] == 168 {
                match o[2] {
                    10 => Some(Arc::from("eth1")),
                    20 => Some(Arc::from("eth2")),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

struct AddrInfo {
    src_ip: String,
    dst_ip: String,
    src_port: String,
    dst_port: String,
}

fn parse_addrs(data: &[u8]) -> AddrInfo {
    let sliced = match SlicedPacket::from_ethernet(data) {
        Ok(s) => s,
        _ => {
            return AddrInfo {
                src_ip: "?".into(),
                dst_ip: "?".into(),
                src_port: "?".into(),
                dst_port: "?".into(),
            };
        }
    };

    let (src_ip, dst_ip) = match &sliced.net {
        Some(NetSlice::Ipv4(ip)) => {
            let h = ip.header();
            (h.source_addr().to_string(), h.destination_addr().to_string())
        }
        Some(NetSlice::Ipv6(ip)) => {
            let h = ip.header();
            (h.source_addr().to_string(), h.destination_addr().to_string())
        }
        _ => ("?".into(), "?".into()),
    };

    let (src_port, dst_port) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            (tcp.source_port().to_string(), tcp.destination_port().to_string())
        }
        Some(TransportSlice::Udp(udp)) => {
            (udp.source_port().to_string(), udp.destination_port().to_string())
        }
        _ => ("?".into(), "?".into()),
    };

    AddrInfo {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    }
}

async fn replay_one_packet(
    daemon: &TestDaemon,
    raw: Vec<u8>,
    iface: Arc<str>,
) -> ProcessOutputWithPacketId {
    daemon.process_raw_with_packet_id(raw, iface).await
}
