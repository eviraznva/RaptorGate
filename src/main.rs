use tokio::sync::mpsc;
use tokio::task;

use std::cmp::min;
use std::sync::Arc;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::Direction;
use tun::AsyncDevice;

use crate::{frame::RealFrame, policy_evaluator::PolicyEvaluator, rule_tree::{ArmEnd, FieldValue, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict}};

mod frame;
mod rule_tree;
mod app_config;
mod grpc_client;
mod policy_evaluator;
mod rule_tree;

#[tokio::main]
async fn main() {
    let config = match app_config::AppConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {e}");
            return;
        }
    };

    let all_devices = match pcap::Device::list() {
        Ok(list) => list,
        Err(err) => {
            eprintln!("Device lookup error: {err:?}");
            return;
        }
    };

    let devices: Vec<pcap::Device> = all_devices
        .into_iter()
        .filter(|dev| config.capture_interfaces.contains(&dev.name))
        .collect();

    if devices.is_empty() {
        eprintln!("No matching devices found");
        return;
    }

    println!(
        "Using devices: {}",
        devices
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let tun = match setup_tun(&config.tun_device_name, config.tun_address, config.tun_netmask) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            eprintln!("Can't set up tun: {e:?}");
            return;
        }
    };

    let evaluator = Arc::new(build_policy(config.block_icmp));

    let pcap_timeout_ms = config.pcap_timeout_ms;
    let mut handles = Vec::new();

    for device in devices {
        let tun = Arc::clone(&tun);
        let evaluator = Arc::clone(&evaluator);
        let name = device.name.clone();
        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);

        let capture_name = name.clone();
        task::spawn_blocking(move || {
            let mut cap = match pcap::Capture::from_device(device)
                .map(|c| c.immediate_mode(true).promisc(true).timeout(pcap_timeout_ms))
                .and_then(pcap::Capture::open)
            {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("[{capture_name}] Failed to open capture: {err:?}");
                    return;
                }
            };

            // FIX: Only capture INCOMING packets.
            // Without this, packets that the kernel forwards out of tun0 back onto
            // enp0s8/enp0s9 are re-captured by pcap, creating an infinite loop.
            // Direction::In uses pcap_setdirection(PCAP_D_IN), which on Linux
            // AF_PACKET sockets excludes packets with sll_pkttype == PACKET_OUTGOING.
            if let Err(e) = cap.direction(Direction::In) {
                eprintln!("[{capture_name}] Warning: could not set direction: {e:?}");
            }

            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        if tx.blocking_send(packet.data.to_vec()).is_err() {
                            eprintln!("[{capture_name}] Receiver dropped, stopping capture");
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // No packet within timeout window — just keep waiting.
                        continue;
                    }
                    Err(err) => {
                        eprintln!("[{capture_name}] Capture error (fatal): {err:?}");
                        break;
                    }
                }
            }
            eprintln!("[{capture_name}] Capture thread exiting");
        });

        let handler_name = name;
        let handle = tokio::spawn(async move {
            let mut rx = rx;
            while let Some(data) = rx.recv().await {
                handle_packet(&handler_name, &data, &tun, &evaluator).await;
            }
            eprintln!("[{handler_name}] Handler task exiting (sender dropped)");
        });

        handles.push(handle);
    }

    for handle in handles {
        if let Err(e) = handle.await {
            eprintln!("Task panicked: {e:?}");
        }
    }
}

/// Inspect a raw Ethernet frame, evaluate it against the firewall policy,
/// and forward it through the TUN device or drop it based on the verdict.
async fn handle_packet(iface: &str, data: &[u8], tun: &AsyncDevice, evaluator: &PolicyEvaluator) {
    let packet = match SlicedPacket::from_ethernet(data) {
        Ok(packet) => packet,
        Err(err) => {
            eprintln!("[{iface}] SlicedPacket parse error: {err:?}");
            return;
        }
    };

    // Only forward IPv4 packets.
    if !matches!(&packet.net, Some(NetSlice::Ipv4(_))) {
        return;
    }

    let verdict = RealFrame::from_sliced(&packet).and_then(|frame| evaluator.evaluate(&frame));

    let allow = matches!(verdict, Some(Verdict::Allow | Verdict::AllowWarn(_)));

    // Log warnings attached to verdict
    match &verdict {
        Some(Verdict::AllowWarn(msg)) => eprintln!("[{iface}] WARN (allow): {msg}"),
        Some(Verdict::DropWarn(msg)) => eprintln!("[{iface}] WARN (drop): {msg}"),
        _ => {}
    }

    let ip_info = match &packet.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            let src = std::net::Ipv4Addr::from(header.source());
            let dst = std::net::Ipv4Addr::from(header.destination());
            let ttl = header.ttl();
            let total_len = header.total_len();
            let (proto, ports) = match &packet.transport {
                Some(TransportSlice::Tcp(tcp)) => (
                    "TCP",
                    format!("{}:{}", tcp.source_port(), tcp.destination_port()),
                ),
                Some(TransportSlice::Udp(udp)) => (
                    "UDP",
                    format!("{}:{}", udp.source_port(), udp.destination_port()),
                ),
                Some(TransportSlice::Icmpv4(_)) => ("ICMP", "-".into()),
                _ => ("OTHER", "-".into()),
            };
            format!("{src} -> {dst} proto={proto} ports={ports} ttl={ttl} len={total_len}")
        }
        _ => "N/A".into(),
    };

    if !allow {
        println!("[{iface}] DROP {ip_info}");
        return;
    }

    println!("[{iface}] PASS {ip_info}");

    if let Some(ip_payload) = packet.ether_payload().map(|ether| ether.payload) {
        match tun.send(ip_payload).await {
            Ok(_) => {}
            Err(e) => eprintln!("[{iface}] Failed to send to tun0: {e}"),
        }
    }
}

fn build_policy(block_icmp: bool) -> PolicyEvaluator {
    use frame::Protocol;

    let tree = if block_icmp {
        RuleTree::new(
            "default".into(),
            "Block ICMP, allow everything else".into(),
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Equal(FieldValue::Protocol(Protocol::Icmp)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .arm(Pattern::Wildcard, ArmEnd::Verdict(Verdict::Allow))
            .build()
            .expect("default policy is valid"),
        )
    } else {
        RuleTree::new(
            "default".into(),
            "Allow everything".into(),
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Wildcard,
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .expect("default policy is valid"),
        )
    };

    PolicyEvaluator::new(tree, Verdict::Drop)
}

fn setup_tun(name: &str, address: std::net::Ipv4Addr, netmask: std::net::Ipv4Addr) -> tun::Result<AsyncDevice> {
    let mut config = tun::Configuration::default();
    config
        .tun_name(name)
        .address(address)
        .netmask(netmask)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    tun::create_as_async(&config)
}
