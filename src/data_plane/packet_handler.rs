use std::sync::Arc;
use tun::AsyncDevice;
use tokio::sync::watch;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::data_plane::nat::dummy_lab::NatLabRuntime;
use crate::data_plane::nat::types::nat_outcome::NatOutcome;
use crate::data_plane::nat::types::nat_stage::NatStage;
use crate::frame::RealFrame;
use crate::rule_tree::Verdict;
use crate::ip_defrag::{DefragResult, IpDefragEngine};
use crate::control_plane::firewall_communication::FirewallRuntimeState;

pub async fn handle_packet(
    iface: &str,
    data: &[u8],
    tun: &AsyncDevice,
    state_rx: &watch::Receiver<Arc<FirewallRuntimeState>>,
    defrag: &Arc<IpDefragEngine>,
    nat: &Arc<NatLabRuntime>,
) {
    let packet = match SlicedPacket::from_ethernet(data) {
        Ok(packet) => packet,
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

    // Pakiet sfragmentowany - przekazanie do silnika skladania.
    if packet.is_ip_payload_fragmented() {
        match defrag.process(&packet) {
            DefragResult::Pending => {}
            DefragResult::Complete(eth_frame) => {
                // Skladanie zakonczone - ponowne parsowanie i przekazanie.
                match SlicedPacket::from_ethernet(&eth_frame) {
                    Ok(reassembled) => forward_packet(iface, &reassembled, tun, state_rx, nat).await,
                    Err(err) => eprintln!("[{iface}] DROP (reassembled packet parse error: {err:?})"),
                }
            }
            DefragResult::CompleteWithAnomaly(eth_frame, anomalies) => {
                // Skladanie zakonczone mimo anomalii - logowanie i przekazanie.
                eprintln!("[{iface}] WARN (defrag anomalies: {})", anomalies.join("; "));
                match SlicedPacket::from_ethernet(&eth_frame) {
                    Ok(reassembled) => forward_packet(iface, &reassembled, tun, state_rx, nat).await,
                    Err(err) => eprintln!("[{iface}] DROP (reassembled packet parse error: {err:?})"),
                }
            }
            DefragResult::Dropped(reason) => {
                println!("[{iface}] DROP (defrag: {reason})");
            }
        }
        return;
    }

    forward_packet(iface, &packet, tun, state_rx, nat).await;
}

// Ocena polityki dla zlozonego lub niesfragmentowanego pakietu i przekazuje go do TUN.
async fn forward_packet(
    iface: &str,
    packet: &SlicedPacket<'_>,
    tun: &AsyncDevice,
    state_rx: &watch::Receiver<Arc<FirewallRuntimeState>>,
    nat: &Arc<NatLabRuntime>,
) {
    let state = state_rx.borrow().clone();
    let compiled_policy = state.compiled_policy().clone();
    let nat_outcome = apply_nat(iface, packet, nat);
    let verdict = RealFrame::from_sliced(&packet)
        .and_then(|frame| compiled_policy.evaluator().evaluate(&frame));

    let policy_allow = matches!(verdict, Some(Verdict::Allow | Verdict::AllowWarn(_)));
    let allow = if nat.allow_all {
        if !policy_allow {
            eprintln!("[{iface}] POLICY BYPASS (dummy NAT lab mode)");
        }
        true
    } else {
        policy_allow
    };

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
        if let Err(err) = tun.send(ip_payload).await {
            eprintln!("[{iface}] Failed to send to tun0: {err}");
        }
    }

    if matches!(nat_outcome, NatOutcome::Created { .. } | NatOutcome::AppliedExisting { .. }) {
        println!("[{iface}] NAT NOTE packet payload was not rewritten yet; current integration logs and tracks flows");
    }
}

fn apply_nat(iface: &str, packet: &SlicedPacket<'_>, nat: &Arc<NatLabRuntime>) -> NatOutcome {
    if !nat.enabled {
        return NatOutcome::NoMatch;
    }

    let (src_ip, dst_ip) = match packet_endpoints(packet) {
        Some(ips) => ips,
        None => return NatOutcome::NoMatch,
    };

    let out_interface = infer_out_interface(dst_ip);
    let in_zone = infer_zone(iface);
    let out_zone = out_interface.and_then(infer_zone);

    let mut engine = match nat.engine.lock() {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!("[{iface}] NAT engine lock poisoned: {err}");
            return NatOutcome::NoMatch;
        }
    };

    let outcome = engine.process_stage(
        packet,
        NatStage::Prerouting,
        true,
        &nat.resolver,
        Some(iface),
        out_interface,
        in_zone,
        out_zone,
    );

    match &outcome {
        NatOutcome::NoMatch => {
            println!("[{iface}] NAT no-match src={src_ip} dst={dst_ip} out_if={out_interface:?} in_zone={in_zone:?} out_zone={out_zone:?}");
        }
        NatOutcome::Created {
            binding_id,
            rule_id,
        } => {
            println!("[{iface}] NAT created binding={binding_id} rule={rule_id} src={src_ip} dst={dst_ip} out_if={out_interface:?} in_zone={in_zone:?} out_zone={out_zone:?}");
        }
        NatOutcome::AppliedExisting {
            binding_id,
            direction,
        } => {
            println!("[{iface}] NAT existing binding={binding_id} direction={direction:?} src={src_ip} dst={dst_ip}");
        }
    }

    outcome
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

fn infer_zone(iface: &str) -> Option<&'static str> {
    match iface {
        "eth1" => Some("internal"),
        "eth2" => Some("dmz"),
        _ => None,
    }
}
