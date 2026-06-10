use std::{path::Path, time::Duration};
use std::sync::Arc;

use pcap::{Capture, Linktype};
use raptorgate_testkit::{
    smoke_tcp_allow_warn_bundle, ProcessOutputWithPacketId, TestDaemon,
};
use tokio::time::sleep;

const WORKSPACE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../");

fn pcap_path(name: &str) -> String {
    let path = Path::new(WORKSPACE_ROOT).join(name);
    path.to_string_lossy().to_string()
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
            let src_mac = if addr_len >= 6 { &data[6..12] } else { &[0u8; 6] };

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
            let src_mac = if addr_len >= 6 { &data[12..18] } else { &[0u8; 6] };

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
    let sliced = etherparse::SlicedPacket::from_ethernet(data).ok()?;
    match sliced.net? {
        etherparse::NetSlice::Ipv4(ip) => {
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

async fn replay_one_packet(
    daemon: &TestDaemon,
    raw: Vec<u8>,
    iface: Arc<str>,
) -> ProcessOutputWithPacketId {
    daemon.process_raw_with_packet_id(raw, iface).await
}

async fn replay_pcap(path: &str) {
    let mut cap = Capture::from_file(path).expect("cannot open pcap file");
    let linktype = cap.get_datalink();
    let file_name = Path::new(path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let daemon = TestDaemon::builder()
        .with_bundle(smoke_tcp_allow_warn_bundle())
        .build()
        .await
        .expect("test daemon");

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

        let result = replay_one_packet(&daemon, raw, iface.clone()).await;

        let pid = result.packet_id.map(|id| id.0).unwrap_or(0);
        let outcome = match &result.output.stage_outcome {
            Some(o) => format!("{o:?}"),
            None => "None".into(),
        };
        let emitted = result.output.emitted.len();

        println!(
            "[{file_name:20}] pkt#{frame_idx:5} {iface:4} \
             pid={pid:<5} outcome={outcome} emitted={emitted}",
        );
    }
}

#[tokio::test]
async fn replay_ssh_failed_handshake() {
    let path = pcap_path("ssh_failed_handshake.pcapng");
    replay_pcap(&path).await;
    sleep(Duration::from_secs(3)).await;
}

#[tokio::test]
async fn replay_ssh_succesful_handshake() {
    let path = pcap_path("ssh_succesful_handshake.pcapng");
    replay_pcap(&path).await;
    sleep(Duration::from_secs(3)).await;
}
