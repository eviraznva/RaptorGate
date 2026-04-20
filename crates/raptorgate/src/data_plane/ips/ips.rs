use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use regex::bytes::Regex;
use anyhow::{Context, Result};
use etherparse::TransportSlice;

use crate::data_plane::ips::config::{
    IpsAction, IpsAppProtocol, IpsConfig, IpsSeverity, IpsSignatureConfig,
};

use crate::dpi::AppProto;
use crate::data_plane::packet_context::PacketContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpsVerdict {
    Allow,
    Alert(String),
    Block(String),
}

pub struct Ips {
    enabled: AtomicBool,
    detection_enabled: AtomicBool,
    state: ArcSwap<CompiledIpsState>,
}

impl Ips {
    pub fn new(config: IpsConfig) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            enabled: AtomicBool::new(config.general.enabled),
            detection_enabled: AtomicBool::new(config.detection.enabled),
            state: ArcSwap::new(Arc::new(CompiledIpsState::from_config(&config)?)),
        }))
    }

    pub fn update_config(&self, config: &IpsConfig) -> Result<()> {
        self.enabled
            .store(config.general.enabled, Ordering::Release);
        self.detection_enabled
            .store(config.detection.enabled, Ordering::Release);
        self.state
            .store(Arc::new(CompiledIpsState::from_config(config)?));
        Ok(())
    }

    pub fn inspect_packet(&self, ctx: &PacketContext) -> IpsVerdict {
        if !self.enabled.load(Ordering::Acquire) || !self.detection_enabled.load(Ordering::Acquire)
        {
            return IpsVerdict::Allow;
        }

        let dpi_ctx = ctx.borrow_dpi_ctx();
        let dpi_app_proto = dpi_ctx.as_ref().and_then(|dpi_ctx| dpi_ctx.app_proto);

        let sliced_packet = ctx.borrow_sliced_packet();
        
        let (payload, src_port, dst_port) = match &sliced_packet.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                (tcp.payload(), tcp.source_port(), tcp.destination_port())
            }
            Some(TransportSlice::Udp(udp)) => {
                (udp.payload(), udp.source_port(), udp.destination_port())
            }
            _ => return IpsVerdict::Allow,
        };

        if payload.is_empty() {
            return IpsVerdict::Allow;
        }

        let state = self.state.load();
        let inspected_payload = dpi_ctx
            .as_ref()
            .and_then(|dpi_ctx| {
                (dpi_ctx.app_proto == Some(AppProto::Http)
                    && dpi_ctx.http_version.as_deref() == Some("2"))
                    .then_some(dpi_ctx.http_normalized_payload.as_deref())
                    .flatten()
            })
            .unwrap_or(payload);
        let inspected = if inspected_payload.len() > state.max_payload_bytes {
            &inspected_payload[..state.max_payload_bytes]
        } else {
            inspected_payload
        };

        let mut alerts = Vec::new();
        let mut matches = 0usize;

        for signature in &state.signatures {
            if matches >= state.max_matches_per_packet {
                break;
            }
            if !signature.matches_filters(dpi_app_proto, src_port, dst_port) {
                continue;
            }
            if !signature.regex.is_match(inspected) {
                continue;
            }

            matches += 1;
            let message = signature.verdict_message();
            if signature.action == IpsAction::Block {
                return IpsVerdict::Block(message);
            }
            alerts.push(message);
        }

        if alerts.is_empty() {
            IpsVerdict::Allow
        } else {
            IpsVerdict::Alert(alerts.join("; "))
        }
    }

    // Inspekcja odszyfrowanego payloadu (bez PacketContext).
    pub fn inspect_decrypted(
        &self,
        payload: &[u8],
        app_proto: Option<AppProto>,
        src_port: u16,
        dst_port: u16,
    ) -> IpsVerdict {
        if !self.enabled.load(Ordering::Acquire) || !self.detection_enabled.load(Ordering::Acquire)
        {
            return IpsVerdict::Allow;
        }

        if payload.is_empty() {
            return IpsVerdict::Allow;
        }

        let state = self.state.load();

        let inspected = if payload.len() > state.max_payload_bytes {
            &payload[..state.max_payload_bytes]
        } else {
            payload
        };

        let mut alerts = Vec::new();
        let mut matches = 0usize;

        for signature in &state.signatures {
            if matches >= state.max_matches_per_packet {
                break;
            }
            if !signature.matches_filters(app_proto, src_port, dst_port) {
                continue;
            }
            if !signature.regex.is_match(inspected) {
                continue;
            }

            matches += 1;
            let message = signature.verdict_message();
            if signature.action == IpsAction::Block {
                return IpsVerdict::Block(message);
            }
            alerts.push(message);
        }

        if alerts.is_empty() {
            IpsVerdict::Allow
        } else {
            IpsVerdict::Alert(alerts.join("; "))
        }
    }
}

#[derive(Clone)]
struct CompiledIpsState {
    max_payload_bytes: usize,
    max_matches_per_packet: usize,
    signatures: Vec<CompiledSignature>,
}

impl CompiledIpsState {
    fn from_config(config: &IpsConfig) -> Result<Self> {
        Ok(Self {
            max_payload_bytes: config.detection.max_payload_bytes,
            max_matches_per_packet: config.detection.max_matches_per_packet,
            signatures: config
                .signatures
                .iter()
                .filter(|signature| signature.enabled)
                .map(CompiledSignature::from_config)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

#[derive(Clone)]
struct CompiledSignature {
    id: String,
    name: String,
    category: String,
    severity: IpsSeverity,
    action: IpsAction,
    app_protocols: Vec<IpsAppProtocol>,
    src_ports: Vec<u16>,
    dst_ports: Vec<u16>,
    regex: Regex,
}

impl CompiledSignature {
    fn from_config(config: &IpsSignatureConfig) -> Result<Self> {
        Ok(Self {
            id: config.id.clone(),
            name: config.name.clone(),
            category: config.category.clone(),
            severity: config.severity,
            action: config.action,
            app_protocols: config.app_protocols.clone(),
            src_ports: config.src_ports.clone(),
            dst_ports: config.dst_ports.clone(),
            regex: Regex::new(&config.pattern)
                .with_context(|| format!("failed to compile ips signature '{}'", config.id))?,
        })
    }

    fn matches_filters(&self, app_proto: Option<AppProto>, src_port: u16, dst_port: u16) -> bool {
        (self.app_protocols.is_empty()
            || app_proto.is_some_and(|proto| {
                self.app_protocols
                    .iter()
                    .any(|filter| filter.matches(proto))
            }))
            && (self.src_ports.is_empty() || self.src_ports.contains(&src_port))
            && (self.dst_ports.is_empty() || self.dst_ports.contains(&dst_port))
    }

    fn verdict_message(&self) -> String {
        format!(
            "IPS {}: signature '{}' matched (id={}, category={}, severity={})",
            self.action.as_str(),
            self.name,
            self.id,
            self.category,
            self.severity.as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use etherparse::PacketBuilder;

    use super::*;
    use crate::data_plane::ips::config::{IpsDetectionConfig, IpsGeneralConfig};
    use crate::dpi::{AppProto, DpiContext};

    fn make_config() -> IpsConfig {
        IpsConfig {
            general: IpsGeneralConfig { enabled: true },
            detection: IpsDetectionConfig {
                enabled: true,
                max_payload_bytes: 512,
                max_matches_per_packet: 4,
            },
            signatures: vec![
                IpsSignatureConfig {
                    id: "http-sqli".into(),
                    name: "SQLi".into(),
                    enabled: true,
                    category: "sqli".into(),
                    pattern: "(?i)union\\s+select".into(),
                    severity: IpsSeverity::High,
                    action: IpsAction::Block,
                    app_protocols: vec![IpsAppProtocol::Http],
                    src_ports: vec![],
                    dst_ports: vec![80],
                },
                IpsSignatureConfig {
                    id: "ua-curl".into(),
                    name: "Curl UA".into(),
                    enabled: true,
                    category: "other".into(),
                    pattern: "(?i)curl/".into(),
                    severity: IpsSeverity::Low,
                    action: IpsAction::Alert,
                    app_protocols: vec![IpsAppProtocol::Http],
                    src_ports: vec![],
                    dst_ports: vec![],
                },
            ],
        }
    }

    fn build_tcp_packet(payload: &[u8], dst_port: u16) -> PacketContext {
        build_tcp_packet_with_ctx(
            payload,
            dst_port,
            DpiContext {
                app_proto: Some(AppProto::Http),
                ..Default::default()
            },
        )
    }

    fn build_tcp_packet_with_ctx(payload: &[u8], dst_port: u16, dpi_ctx: DpiContext) -> PacketContext {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(12345, dst_port, 1, 1024);

        let mut raw = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut raw, payload)
            .expect("packet should serialize");

        PacketContext::from_raw_full(
            raw,
            Arc::<str>::from("eth1"),
            Vec::new(),
            SystemTime::now(),
            Some(dpi_ctx),
        )
        .expect("packet context should parse")
    }

    #[test]
    fn block_signature_halts_packet() {
        let ips = Ips::new(make_config()).expect("ips should initialize");
        let ctx = build_tcp_packet(b"GET /?q=UNION SELECT 1 HTTP/1.1\r\nHost: x\r\n\r\n", 80);

        let verdict = ips.inspect_packet(&ctx);
        assert!(matches!(verdict, IpsVerdict::Block(msg) if msg.contains("SQLi")));
    }

    #[test]
    fn alert_signature_warns_without_block() {
        let ips = Ips::new(make_config()).expect("ips should initialize");
        let ctx = build_tcp_packet(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0.1\r\n\r\n",
            8080,
        );

        let verdict = ips.inspect_packet(&ctx);
        assert!(matches!(verdict, IpsVerdict::Alert(msg) if msg.contains("Curl UA")));
    }

    #[test]
    fn protocol_filter_prevents_match_without_dpi_context() {
        let ips = Ips::new(make_config()).expect("ips should initialize");
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(12345, 80, 1, 1024);
        let mut raw = Vec::with_capacity(builder.size(64));
        builder
            .write(
                &mut raw,
                b"GET /?q=UNION SELECT 1 HTTP/1.1\r\nHost: x\r\n\r\n",
            )
            .expect("packet should serialize");
        let ctx = PacketContext::from_raw_full(
            raw,
            Arc::<str>::from("eth1"),
            Vec::new(),
            SystemTime::now(),
            None,
        )
        .expect("packet context should parse");

        assert_eq!(ips.inspect_packet(&ctx), IpsVerdict::Allow);
    }

    #[test]
    fn update_config_hot_swaps_signatures() {
        let ips = Ips::new(make_config()).expect("ips should initialize");
        let before = build_tcp_packet(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0.1\r\n\r\n",
            8080,
        );
        assert!(matches!(ips.inspect_packet(&before), IpsVerdict::Alert(_)));

        let mut new_config = make_config();
        new_config.signatures[1].pattern = "(?i)wget/".into();
        ips.update_config(&new_config)
            .expect("config should hot swap");

        let after = build_tcp_packet(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0.1\r\n\r\n",
            8080,
        );
        assert_eq!(ips.inspect_packet(&after), IpsVerdict::Allow);
    }

    #[test]
    fn global_disable_skips_detection() {
        let mut config = make_config();
        config.general.enabled = false;
        let ips = Ips::new(config).expect("ips should initialize");
        let ctx = build_tcp_packet(b"GET /?q=UNION SELECT 1 HTTP/1.1\r\nHost: x\r\n\r\n", 80);

        assert_eq!(ips.inspect_packet(&ctx), IpsVerdict::Allow);
    }

    #[test]
    fn http2_uses_normalized_payload_for_matching() {
        let ips = Ips::new(make_config()).expect("ips should initialize");
        let ctx = build_tcp_packet_with_ctx(
            b"\x00\x00\x00\x01",
            80,
            DpiContext {
                app_proto: Some(AppProto::Http),
                http_version: Some("2".into()),
                http_normalized_payload: Some(
                    b"GET /search?q=UNION SELECT HTTP/2\r\nHost: example.com\r\n\r\n".to_vec(),
                ),
                ..Default::default()
            },
        );

        let verdict = ips.inspect_packet(&ctx);
        assert!(matches!(verdict, IpsVerdict::Block(msg) if msg.contains("SQLi")));
    }
}
