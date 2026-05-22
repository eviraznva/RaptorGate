use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashMap;
use pcap::Direction;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::{AppConfig, ConfigObserver};
use crate::data_plane::packet_context::CaptureDirection;
use crate::events::{emit, Event, EventKind};

fn calculate_retry_delay(attempt: u32) -> Duration {
    if attempt <= 5 {
        Duration::from_millis(50)
    } else {
        Duration::from_millis(5000)
    }
}

/// Raw packet data as captured from the NIC, before parsing or reassembly.
pub struct RawPacket {
    pub raw: Vec<u8>,
    pub iface: Arc<str>,
    pub capture_direction: CaptureDirection,
}

pub struct InterfaceSniffer {
    tx: mpsc::Sender<RawPacket>,
    handles: DashMap<String, CancellationToken>,
    pcap_timeout_ms: AtomicI32,
    #[cfg(test)]
    test_mode: bool,
}

impl InterfaceSniffer {
    pub fn with_sniffing(pcap_timeout_ms: i32) -> (Self, mpsc::Receiver<RawPacket>) {
        let (tx, rx) = mpsc::channel(1024);
        let sniffer = Self {
            tx,
            handles: DashMap::new(),
            pcap_timeout_ms: AtomicI32::new(pcap_timeout_ms),
            #[cfg(test)]
            test_mode: false,
        };
        (sniffer, rx)
    }

    pub fn reconcile_capture_interfaces(&self, sniffed_interfaces: &[String]) {
        let old: Vec<String> = self.handles.iter().map(|e| e.key().clone()).collect();
        tracing::debug!(
            event = "sniffer.reconcile.requested",
            requested = ?sniffed_interfaces,
            active = ?old,
            requested_count = sniffed_interfaces.len(),
            active_count = old.len(),
            "reconciling packet capture interfaces"
        );
        for iface in &old {
            if !sniffed_interfaces.contains(iface) {
                self.cancel_sniffing(iface);
            }
        }
        for iface in sniffed_interfaces {
            if !self.handles.contains_key(iface) {
                tracing::info!(
                    event = "sniffer.reconcile.start_interface",
                    iface = %iface,
                    "starting capture for reconciled interface"
                );
                if let Err(e) = self.sniff_new(iface.clone()) {
                    tracing::error!(
                        event = "sniffer.reconcile.failed",
                        iface = %iface,
                        error = %e,
                        "failed to start sniffing interface during reconciliation"
                    );
                }
            }
        }
    }

    pub fn sniff_new(&self, iface: String) -> Result<(), SnifferError> {
        if self.handles.contains_key(&iface) {
            tracing::warn!(
                event = "sniffer.start.skipped",
                iface = %iface,
                "already sniffing interface, ignoring"
            );
            return Ok(());
        }

        #[cfg(test)]
        if self.test_mode {
            let token = CancellationToken::new();
            self.handles.insert(iface, token);
            return Ok(());
        }

        let token = CancellationToken::new();
        let tx = self.tx.clone();
        let child = token.child_token();
        let name = iface.clone();
        let timeout = self.pcap_timeout_ms.load(Ordering::Relaxed);
        let local_mac = read_interface_mac(&name);

        let mut cap = match Self::open_capture(&name, timeout) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    event = "sniffer.capture.open_failed",
                    iface = %name,
                    error = %e,
                    "failed to open capture"
                );
                return Err(e.into());
            }
        };

        tracing::info!(
            event = "sniffer.capture.started",
            iface = %name,
            timeout_ms = timeout,
            "packet capture started"
        );

        tokio::task::spawn_blocking(move || {
            let iface_arc: Arc<str> = Arc::from(name.as_str());
            let mut attempt = 0u32;
            let mut total_downtime_ms = 0u64;

            'reconnect: loop {
                loop {
                    if child.is_cancelled() {
                        tracing::info!(
                            event = "sniffer.capture.cancelled",
                            iface = %name,
                            "capture cancelled"
                        );
                        break 'reconnect;
                    }

                    match cap.next_packet() {
                        Ok(pkt) => {
                            let packet_len = pkt.data.len();
                            let capture_direction = classify_capture_direction(pkt.data, local_mac);
                            let packet = RawPacket {
                                raw: pkt.data.to_vec(),
                                iface: Arc::clone(&iface_arc),
                                capture_direction,
                            };

                            tracing::trace!(
                                event = "sniffer.packet.captured",
                                iface = %name,
                                packet_len,
                                "packet captured from interface"
                            );
                            if tx.blocking_send(packet).is_err() {
                                tracing::info!(
                                    event = "sniffer.capture.stopped",
                                    iface = %name,
                                    reason = "channel_closed",
                                    "channel closed, stopping capture"
                                );
                                break 'reconnect;
                            }
                            tracing::trace!(
                                event = "sniffer.packet.enqueued",
                                iface = %name,
                                packet_len,
                                "captured packet enqueued for pipeline"
                            );
                        }
                        Err(pcap::Error::TimeoutExpired) => {}
                        Err(e) => {
                            tracing::error!(
                                event = "sniffer.capture.failed",
                                iface = %name,
                                error = %e,
                                "capture error, entering retry mode"
                            );
                            break;
                        }
                    }
                }

                loop {
                    attempt += 1;
                    let delay = calculate_retry_delay(attempt);
                    let delay_ms = delay.as_millis() as u64;

                    emit(Event::new(EventKind::SnifferReconnecting {
                        iface: name.clone(),
                        attempt,
                        next_retry_ms: delay_ms,
                    }));

                    tracing::info!(
                        event = "sniffer.reconnect.attempt",
                        iface = %name,
                        attempt,
                        delay_ms,
                        "attempting reconnection"
                    );

                    std::thread::sleep(delay);
                    total_downtime_ms += delay_ms;

                    if child.is_cancelled() {
                        tracing::info!(
                            event = "sniffer.capture.cancelled",
                            iface = %name,
                            "capture cancelled during reconnect"
                        );
                        break 'reconnect;
                    }

                    match Self::open_capture(&name, timeout) {
                        Ok(new_cap) => {
                            cap = new_cap;
                            emit(Event::new(EventKind::SnifferReconnected {
                                iface: name.clone(),
                                total_attempts: attempt,
                                total_downtime_ms,
                            }));
                            tracing::info!(
                                event = "sniffer.reconnect.success",
                                iface = %name,
                                total_attempts = attempt,
                                total_downtime_ms,
                                "reconnected successfully"
                            );
                            attempt = 0;
                            total_downtime_ms = 0;
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(
                                event = "sniffer.reconnect.failed",
                                iface = %name,
                                attempt,
                                error = %e,
                                "reconnection attempt failed"
                            );
                        }
                    }
                }
            }
        });

        self.handles.insert(iface, token);
        Ok(())
    }

    pub fn cancel_sniffing(&self, iface: &str) {
        match self.handles.remove(iface) {
            Some((_, token)) => {
                token.cancel();
                tracing::info!(
                    event = "sniffer.capture.cancel_requested",
                    iface = %iface,
                    "capture cancellation requested"
                );
            }
            None => {
                tracing::warn!(
                    event = "sniffer.capture.cancel_skipped",
                    iface = %iface,
                    "cancel_sniffing called for unknown interface"
                );
            }
        }
    }

    pub fn cancel_all(&self) {
        for entry in &self.handles {
            entry.value().cancel();
            tracing::info!(
                event = "sniffer.capture.cancel_requested",
                iface = %entry.key(),
                "capture cancellation requested"
            );
        }
    }

    fn open_capture(iface: &str, timeout_ms: i32) -> Result<pcap::Capture<pcap::Active>, pcap::Error> {
        let device = pcap::Device::list()?
            .into_iter()
            .find(|d| d.name == iface)
            .ok_or_else(|| pcap::Error::PcapError(format!("interface '{iface}' not found")))?;

        let cap = pcap::Capture::from_device(device)?
            .immediate_mode(true)
            .promisc(true)
            .timeout(timeout_ms)
            .open()?;
        if let Err(e) = cap.direction(Direction::In) {
            tracing::warn!(
                event = "sniffer.capture.direction_failed",
                iface = %iface,
                error = %e,
                "could not set capture direction, capturing all"
            );
        }

        Ok(cap)
    }

    #[cfg(test)]
    pub fn new_for_test() -> (Self, mpsc::Receiver<RawPacket>) {
        let (tx, rx) = mpsc::channel(1024);
        let sniffer = Self {
            tx,
            handles: DashMap::new(),
            pcap_timeout_ms: AtomicI32::new(100),
            test_mode: true,
        };
        (sniffer, rx)
    }

    #[cfg(test)]
    pub fn insert_test_handle(&self, iface: String) {
        let token = CancellationToken::new();
        self.handles.insert(iface, token);
    }

    #[cfg(test)]
    pub fn has_handle(&self, iface: &str) -> bool {
        self.handles.contains_key(iface)
    }
}

fn classify_capture_direction(packet: &[u8], local_mac: Option<[u8; 6]>) -> CaptureDirection {
    let Some(local_mac) = local_mac else {
        return CaptureDirection::Ingress;
    };
    let Some(src_mac) = packet.get(6..12) else {
        return CaptureDirection::Ingress;
    };

    if src_mac == local_mac {
        CaptureDirection::Egress
    } else {
        CaptureDirection::Ingress
    }
}

fn read_interface_mac(iface: &str) -> Option<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let raw = std::fs::read_to_string(path).ok()?;
    parse_mac(raw.trim())
}

fn parse_mac(raw: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = raw.split(':').collect();
    let [a, b, c, d, e, f] = parts.as_slice() else {
        return None;
    };

    Some([
        u8::from_str_radix(a, 16).ok()?,
        u8::from_str_radix(b, 16).ok()?,
        u8::from_str_radix(c, 16).ok()?,
        u8::from_str_radix(d, 16).ok()?,
        u8::from_str_radix(e, 16).ok()?,
        u8::from_str_radix(f, 16).ok()?,
    ])
}

#[derive(Debug, Error)]
pub enum SnifferError {
    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),
}

#[tonic::async_trait]
impl ConfigObserver for InterfaceSniffer {
    async fn on_config_change(&self, new_config: &AppConfig) -> Result<()> {
        self.pcap_timeout_ms.store(new_config.pcap_timeout_ms, Ordering::Relaxed);
        tracing::info!(
            event = "sniffer.config.changed",
            pcap_timeout_ms = new_config.pcap_timeout_ms,
            "sniffer pcap timeout updated"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_retry_delay() {
        assert_eq!(calculate_retry_delay(1), Duration::from_millis(50));
        assert_eq!(calculate_retry_delay(5), Duration::from_millis(50));
        assert_eq!(calculate_retry_delay(6), Duration::from_millis(5000));
        assert_eq!(calculate_retry_delay(10), Duration::from_millis(5000));
    }

    #[test]
    fn test_reconcile_starts_sniffing_new_interfaces() {
        let (sniffer, _rx) = InterfaceSniffer::new_for_test();
        assert!(!sniffer.has_handle("eth0"));
        
        sniffer.reconcile_capture_interfaces(&["eth0".to_string()]);
        
        assert!(sniffer.has_handle("eth0"));
    }

    #[test]
    fn test_reconcile_stops_removed_interfaces() {
        let (sniffer, _rx) = InterfaceSniffer::new_for_test();
        sniffer.insert_test_handle("eth0".to_string());
        assert!(sniffer.has_handle("eth0"));
        
        sniffer.reconcile_capture_interfaces(&["eth1".to_string()]);
        
        assert!(!sniffer.has_handle("eth0"));
        assert!(sniffer.has_handle("eth1"));
    }

    #[test]
    fn test_reconcile_idempotent() {
        let (sniffer, _rx) = InterfaceSniffer::new_for_test();
        
        sniffer.reconcile_capture_interfaces(&["eth0".to_string()]);
        assert!(sniffer.has_handle("eth0"));
        assert_eq!(sniffer.handles.len(), 1);
        
        sniffer.reconcile_capture_interfaces(&["eth0".to_string()]);
        assert!(sniffer.has_handle("eth0"));
        assert_eq!(sniffer.handles.len(), 1);
    }

    #[test]
    fn test_reconcile_empty_stops_all() {
        let (sniffer, _rx) = InterfaceSniffer::new_for_test();
        sniffer.insert_test_handle("eth0".to_string());
        sniffer.insert_test_handle("eth1".to_string());
        assert_eq!(sniffer.handles.len(), 2);
        
        sniffer.reconcile_capture_interfaces(&[]);
        
        assert_eq!(sniffer.handles.len(), 0);
    }

    #[tokio::test]
    async fn test_config_change_only_updates_timeout() {
        let (sniffer, _rx) = InterfaceSniffer::new_for_test();
        sniffer.insert_test_handle("eth0".to_string());
        assert_eq!(sniffer.pcap_timeout_ms.load(Ordering::Relaxed), 100);
        
        let new_config = AppConfig {
            pcap_timeout_ms: 250,
            tun_device_name: "tun0".to_string(),
            tun_address: "10.0.0.1".parse().unwrap(),
            tun_netmask: "255.255.255.0".parse().unwrap(),
            data_dir: "/tmp".into(),
            event_socket_path: "/tmp/events.sock".to_string(),
            query_socket_path: "/tmp/query.sock".to_string(),
            dev_config: None,
            pki_dir: "/tmp/pki".to_string(),
            ssl_inspection_enabled: false,
            mitm_listen_addr: "127.0.0.1:8443".to_string(),
            control_plane_socket_path: "/tmp/control.sock".to_string(),
            server_cert_socket_path: "/tmp/cert.sock".to_string(),
            ssl_bypass_domains: vec![],
            tls_inspection_ports: vec![443],
            block_tls_on_undeclared_ports: false,
        };
        
        sniffer.on_config_change(&new_config).await.unwrap();
        
        assert_eq!(sniffer.pcap_timeout_ms.load(Ordering::Relaxed), 250);
        assert!(sniffer.has_handle("eth0"));
        assert_eq!(sniffer.handles.len(), 1);
    }

}
