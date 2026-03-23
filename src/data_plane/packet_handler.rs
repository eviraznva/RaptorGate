use std::sync::Arc;

use tun::AsyncDevice;

use tokio::sync::Mutex;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::frame::RealFrame;
use crate::rule_tree::Verdict;
use crate::data_plane::nat::engine::NatEngine;
use crate::data_plane::policy_store::PolicyStore;
use crate::ip_defrag::{DefragResult, IpDefragEngine};
use crate::data_plane::nat::types::nat_outcome::NatOutcome;

const ETH_HDR: usize = 14;

pub async fn handle_packet(
    iface: &str,
    data: &[u8],
    tun: &AsyncDevice,
    policies: &PolicyStore,
    defrag: &Arc<IpDefragEngine>,
    nat: &Arc<Mutex<NatEngine>>,
) {
    let packet = match SlicedPacket::from_ethernet(data) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("[{iface}] SlicedPacket parse error: {err:?}");
            return;
        }
    };

    if !matches!(&packet.net, Some(NetSlice::Ipv4(_))) {
        return;
    }

    if let Err(reason) = crate::packet_validator::validate(&packet) {
        println!("[{iface}] DROP (invalid packet: {reason})");
        return;
    }
    
    drop(packet);
    
    let mut buf = data.to_vec();
    let pre_outcome = nat.lock().await.process_prerouting(&mut buf, iface, None);
    
    log_nat_outcome("PREROUTING", iface, &pre_outcome);
    
    let packet = match SlicedPacket::from_ethernet(&buf) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("[{iface}] SlicedPacket reparse error: {err:?}");
            return;
        }
    };

    if packet.is_ip_payload_fragmented() {
        drop(packet);
        match defrag.process(&SlicedPacket::from_ethernet(&buf).unwrap()) {
            DefragResult::Pending => {}
            DefragResult::Complete(eth_frame) => {
                forward_packet(iface, &eth_frame, tun, policies, nat).await;
            }
            DefragResult::CompleteWithAnomaly(eth_frame, anomalies) => {
                eprintln!("[{iface}] WARN (defrag anomalies: {})", anomalies.join("; "));
                forward_packet(iface, &eth_frame, tun, policies, nat).await;
            }
            DefragResult::Dropped(reason) => {
                println!("[{iface}] DROP (defrag: {reason})");
            }
        }
        return;
    }

    drop(packet);
    forward_packet(iface, &buf, tun, policies, nat).await;
}

async fn forward_packet(
    iface: &str,
    raw: &[u8],
    tun: &AsyncDevice,
    policies: &PolicyStore,
    nat: &Arc<Mutex<NatEngine>>,
) {
    let packet = match SlicedPacket::from_ethernet(raw) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("[{iface}] SlicedPacket forward-parse error: {err:?}");
            return;
        }
    };

    let compiled_policy = policies.load();
    let frame = RealFrame::from_sliced(&packet);
    let verdict = frame.as_ref().and_then(|f| compiled_policy.evaluator().evaluate(f));

    let allow = matches!(verdict, Some(Verdict::Allow | Verdict::AllowWarn(_)));

    match &verdict {
        Some(Verdict::AllowWarn(msg)) => eprintln!("[{iface}] WARN (allow): {msg}"),
        Some(Verdict::DropWarn(msg))  => eprintln!("[{iface}] WARN (drop): {msg}"),
        _ => {}
    }

    let ip_info = match &packet.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            let src       = std::net::Ipv4Addr::from(header.source());
            let dst       = std::net::Ipv4Addr::from(header.destination());
            let ttl       = header.ttl();
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
        tracing::debug!(iface, %ip_info, "DROP");
        return;
    }
    
    let out_iface = packet_endpoints(&packet)
        .and_then(|(_, dst)| infer_out_interface(dst))
        .unwrap_or(iface);
    
    let mut raw_mut = raw.to_vec();
    let outcome = nat.lock().await.process_postrouting(&mut raw_mut, out_iface, None);
    
    log_nat_outcome("POSTROUTING", iface, &outcome);

    tracing::debug!(iface, %ip_info, "PASS");
    
    if raw_mut.len() > ETH_HDR {
        if let Err(err) = tun.send(&raw_mut[ETH_HDR..]).await {
            eprintln!("[{iface}] Failed to send to tun0: {err}");
        }
    }
}

fn log_nat_outcome(stage: &str, iface: &str, outcome: &NatOutcome) {
    match outcome {
        NatOutcome::NoMatch => {}
        NatOutcome::Created { binding_id, rule_id } => {
            tracing::info!(stage, iface, binding_id, rule_id, "NAT: new binding created");
        }
        NatOutcome::AppliedExisting { binding_id, direction } => {
            tracing::debug!(stage, iface, binding_id, ?direction, "NAT: existing binding applied");
        }
    }
}

fn packet_endpoints(packet: &SlicedPacket<'_>) -> Option<(std::net::IpAddr, std::net::IpAddr)> {
    match packet.net.as_ref()? {
        NetSlice::Ipv4(ipv4) => Some((
            std::net::IpAddr::V4(ipv4.header().source_addr()),
            std::net::IpAddr::V4(ipv4.header().destination_addr()),
        )),
        NetSlice::Ipv6(ipv6) => Some((
            std::net::IpAddr::V6(ipv6.header().source_addr()),
            std::net::IpAddr::V6(ipv6.header().destination_addr()),
        )),
        _ => None,
    }
}

fn infer_out_interface(dst_ip: std::net::IpAddr) -> Option<&'static str> {
    match dst_ip {
        std::net::IpAddr::V4(ip) if ip.octets()[0..3] == [192, 168, 10] => Some("eth1"),
        std::net::IpAddr::V4(ip) if ip.octets()[0..3] == [192, 168, 20] => Some("eth2"),
        _ => None,
    }
}
