use std::sync::Arc;

use dashmap::DashMap;
use pcap::Direction;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::AppConfig;

/// Raw packet data as captured from the NIC, before parsing or reassembly.
pub struct RawPacket {
    pub raw: Vec<u8>,
    pub iface: Arc<str>,
}

pub struct InterfaceSniffer {
    tx: mpsc::Sender<RawPacket>,
    handles: DashMap<String, CancellationToken>,
    pcap_timeout_ms: i32,
}

impl InterfaceSniffer {
    pub fn with_sniffing(
        config: &AppConfig,
    ) -> (Self, mpsc::Receiver<RawPacket>, Vec<SnifferError>) {
        let (tx, rx) = mpsc::channel(1024);
        let mut sniffer = Self {
            tx,
            handles: DashMap::new(),
            pcap_timeout_ms: config.pcap_timeout_ms,
        };

        let mut errs = Vec::<SnifferError>::new();
        for iface in &config.capture_interfaces {
            if let Err(err) = sniffer.sniff_new(iface.clone()) {
                errs.push(err);
            }
        }

        (sniffer, rx, errs)
    }

    pub fn sniff_new(&mut self, iface: String) -> Result<(), SnifferError> {
        if self.handles.contains_key(&iface) {
            tracing::warn!(iface = %iface, "already sniffing interface, ignoring");
            return Ok(());
        }

        let token = CancellationToken::new();
        let tx = self.tx.clone();
        let child = token.child_token();
        let name = iface.clone();

        let mut cap = match self.open_capture(&name) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(iface = %name, error = %e, "failed to open capture");
                return Err(e.into());
            }
        };

        tokio::task::spawn_blocking(move || {
            let iface_arc: Arc<str> = Arc::from(name.as_str());

            loop {
                if child.is_cancelled() {
                    tracing::info!(iface = %name, "capture cancelled");
                    break;
                }

                match cap.next_packet() {
                    Ok(pkt) => {
                        let packet = RawPacket {
                            raw: pkt.data.to_vec(),
                            iface: Arc::clone(&iface_arc),
                        };
                        if tx.blocking_send(packet).is_err() {
                            tracing::info!(iface = %name, "channel closed, stopping capture");
                            break;
                        }
                    }
                    // TODO: check if there's a way to cancel immediately without waiting for timeout
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => {
                        tracing::error!(iface = %name, error = %e, "capture error, stopping");
                        break;
                    }
                }
            }
        });

        self.handles.insert(iface, token);
        Ok(())
    }

    pub fn cancel_sniffing(&mut self, iface: &str) {
        match self.handles.remove(iface) {
            Some((_, token)) => {
                token.cancel();
                tracing::info!(iface = %iface, "capture cancellation requested");
            }
            None => {
                tracing::warn!(iface = %iface, "cancel_sniffing called for unknown interface");
            }
        }
    }

    pub fn cancel_all(&self) {
        for entry in &self.handles {
            entry.value().cancel();
            tracing::info!(iface = %entry.key(), "capture cancellation requested");
        }
    }

    fn open_capture(&self, iface: &str) -> Result<pcap::Capture<pcap::Active>, pcap::Error> {
        let device = pcap::Device::list()?
            .into_iter()
            .find(|d| d.name == iface)
            .ok_or_else(|| pcap::Error::PcapError(format!("interface '{iface}' not found")))?;

        let cap = pcap::Capture::from_device(device)?
            .immediate_mode(true)
            .promisc(true)
            .timeout(self.pcap_timeout_ms)
            .open()?;
        if let Err(e) = cap.direction(Direction::In) {
            tracing::warn!(iface = %iface, error = %e, "could not set capture direction, capturing all");
        }

        Ok(cap)
    }
}

#[derive(Debug, Error)]
pub enum SnifferError {
    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),
}
