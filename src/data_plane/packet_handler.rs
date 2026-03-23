use std::sync::Arc;

use tun::AsyncDevice;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::data_plane::policy_store::PolicyStore;
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::frame::RealFrame;
use crate::ip_defrag::{DefragResult, IpDefragEngine};
use crate::rule_tree::Verdict;

pub async fn handle_packet(iface: &str, data: &[u8], tun: &AsyncDevice, policies: &PolicyStore, defrag: &Arc<IpDefragEngine>, tcp_sessions: &TcpSessionTracker) {
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
                    Ok(reassembled) => forward_packet(iface, &reassembled, tun, policies, tcp_sessions).await,
                    Err(err) => eprintln!("[{iface}] DROP (reassembled packet parse error: {err:?})"),
                }
            }
            DefragResult::CompleteWithAnomaly(eth_frame, anomalies) => {
                // Skladanie zakonczone mimo anomalii - logowanie i przekazanie.
                eprintln!("[{iface}] WARN (defrag anomalies: {})", anomalies.join("; "));
                match SlicedPacket::from_ethernet(&eth_frame) {
                    Ok(reassembled) => forward_packet(iface, &reassembled, tun, policies, tcp_sessions).await,
                    Err(err) => eprintln!("[{iface}] DROP (reassembled packet parse error: {err:?})"),
                }
            }
            DefragResult::Dropped(reason) => {
                println!("[{iface}] DROP (defrag: {reason})");
            }
        }
        return;
    }

    forward_packet(iface, &packet, tun, policies, tcp_sessions).await;
}

// Ocena polityki dla zlozonego lub niesfragmentowanego pakietu i przekazuje go do TUN.
async fn forward_packet(iface: &str, packet: &SlicedPacket<'_>, tun: &AsyncDevice, policies: &PolicyStore, tcp_sessions: &TcpSessionTracker) {
    let compiled_policy = policies.load();
    let verdict = RealFrame::from_sliced(packet)
        .and_then(|frame| compiled_policy.evaluator().evaluate(&frame));

    let allowed_tcp = match tcp_sessions.process_packet(packet) {
        Ok(state) => { 
            #[cfg(debug_assertions)]
            if state.is_some() {
                println!("sessions: {:?}", tcp_sessions.get_sessions_between([192, 168, 10], [192, 168, 20]));
            }

            true 
        },
        Err(err) => {
            eprintln!("Rejected tcp with {err}");
            false
        }
    };

    let allowed_policy = matches!(verdict, Some(Verdict::Allow | Verdict::AllowWarn(_)));

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

    if !allowed_policy || !allowed_tcp {
        println!("[{iface}] DROP {ip_info}");
        return;
    }

    println!("[{iface}] PASS {ip_info}");

    if let Some(ip_payload) = packet.ether_payload().map(|ether| ether.payload) {
        if let Err(err) = tun.send(ip_payload).await {
            eprintln!("[{iface}] Failed to send to tun0: {err}");
        }
    }
}
