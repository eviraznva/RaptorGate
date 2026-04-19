use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use regex::bytes::Regex;
use anyhow::{Context, Result};
use etherparse::TransportSlice;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

use crate::data_plane::ips::config::{
    IpsAction, IpsAppProtocol, IpsConfig, IpsMatchType, IpsSeverity, IpsSignatureConfig,
    decode_literal_pattern,
};

use crate::dpi::AppProto;
use crate::data_plane::packet_context::PacketContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpsVerdict {
    Allow,
    Alert(Vec<IpsSignatureMatch>),
    Block(IpsSignatureMatch),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsSignatureMatch {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: IpsSeverity,
    pub action: IpsAction,
}

impl IpsSignatureMatch {
    pub fn message(&self) -> String {
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

        let dpi_app_proto = ctx
            .borrow_dpi_ctx()
            .as_ref()
            .and_then(|dpi_ctx| dpi_ctx.app_proto);

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
        
        let inspected = if payload.len() > state.max_payload_bytes {
            &payload[..state.max_payload_bytes]
        } else {
            payload
        };

        state.inspect(inspected, dpi_app_proto, src_port, dst_port)
    }
}

struct CompiledIpsState {
    max_payload_bytes: usize,
    max_matches_per_packet: usize,
    literal_ac: Option<AhoCorasick>,
    literal_signatures: Vec<CompiledSignature>,
    literal_ci_ac: Option<AhoCorasick>,
    literal_ci_signatures: Vec<CompiledSignature>,
    regex_signatures: Vec<CompiledRegexSignature>,
}

impl CompiledIpsState {
    fn from_config(config: &IpsConfig) -> Result<Self> {
        let mut literal_patterns = Vec::new();
        let mut literal_signatures = Vec::new();
        let mut literal_ci_patterns = Vec::new();
        let mut literal_ci_signatures = Vec::new();
        let mut regex_signatures = Vec::new();

        for signature in config.signatures.iter().filter(|signature| signature.enabled) {
            let compiled = CompiledSignature::from_config(signature);

            match signature.match_type {
                IpsMatchType::Literal => {
                    let pattern = decode_literal_pattern(
                        &signature.pattern,
                        signature.pattern_encoding,
                    )
                    .with_context(|| {
                        format!("failed to decode ips signature '{}'", signature.id)
                    })?;

                    if signature.case_insensitive {
                        literal_ci_patterns.push(pattern);
                        literal_ci_signatures.push(compiled);
                    } else {
                        literal_patterns.push(pattern);
                        literal_signatures.push(compiled);
                    }
                }
                IpsMatchType::Regex => {
                    regex_signatures.push(CompiledRegexSignature::from_config(signature)?);
                }
            }
        }

        Ok(Self {
            max_payload_bytes: config.detection.max_payload_bytes,
            max_matches_per_packet: config.detection.max_matches_per_packet,
            literal_ac: build_automaton(&literal_patterns, false)?,
            literal_signatures,
            literal_ci_ac: build_automaton(&literal_ci_patterns, true)?,
            literal_ci_signatures,
            regex_signatures,
        })
    }

    fn inspect(
        &self,
        payload: &[u8],
        app_proto: Option<AppProto>,
        src_port: u16,
        dst_port: u16,
    ) -> IpsVerdict {
        let mut alerts = Vec::new();
        let mut matches = 0usize;

        if let Some(block) = self.inspect_automaton(
            &self.literal_ac,
            &self.literal_signatures,
            payload,
            app_proto,
            src_port,
            dst_port,
            &mut matches,
            &mut alerts,
        ) {
            return IpsVerdict::Block(block);
        }

        if let Some(block) = self.inspect_automaton(
            &self.literal_ci_ac,
            &self.literal_ci_signatures,
            payload,
            app_proto,
            src_port,
            dst_port,
            &mut matches,
            &mut alerts,
        ) {
            return IpsVerdict::Block(block);
        }

        for signature in &self.regex_signatures {
            if matches >= self.max_matches_per_packet {
                break;
            }
            if !signature.signature.matches_filters(app_proto, src_port, dst_port) {
                continue;
            }
            if !signature.regex.is_match(payload) {
                continue;
            }

            matches += 1;
            let signature_match = signature.signature.to_match();
            if signature.signature.action == IpsAction::Block {
                return IpsVerdict::Block(signature_match);
            }
            alerts.push(signature_match);
        }

        if alerts.is_empty() {
            IpsVerdict::Allow
        } else {
            IpsVerdict::Alert(alerts)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_automaton(
        &self,
        ac: &Option<AhoCorasick>,
        signatures: &[CompiledSignature],
        payload: &[u8],
        app_proto: Option<AppProto>,
        src_port: u16,
        dst_port: u16,
        matches: &mut usize,
        alerts: &mut Vec<IpsSignatureMatch>,
    ) -> Option<IpsSignatureMatch> {
        let ac = ac.as_ref()?;

        for matched in ac.find_iter(payload) {
            if *matches >= self.max_matches_per_packet {
                break;
            }

            let signature = &signatures[matched.pattern().as_usize()];
            
            if !signature.matches_filters(app_proto, src_port, dst_port) {
                continue;
            }

            *matches += 1;
            
            let signature_match = signature.to_match();
            
            if signature.action == IpsAction::Block {
                return Some(signature_match);
            }
            
            alerts.push(signature_match);
        }

        None
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
}

impl CompiledSignature {
    fn from_config(config: &IpsSignatureConfig) -> Self {
        Self {
            id: config.id.clone(),
            name: config.name.clone(),
            category: config.category.clone(),
            severity: config.severity,
            action: config.action,
            app_protocols: config.app_protocols.clone(),
            src_ports: config.src_ports.clone(),
            dst_ports: config.dst_ports.clone(),
        }
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

    fn to_match(&self) -> IpsSignatureMatch {
        IpsSignatureMatch {
            id: self.id.clone(),
            name: self.name.clone(),
            category: self.category.clone(),
            severity: self.severity,
            action: self.action,
        }
    }
}

#[derive(Clone)]
struct CompiledRegexSignature {
    signature: CompiledSignature,
    regex: Regex,
}

impl CompiledRegexSignature {
    fn from_config(config: &IpsSignatureConfig) -> Result<Self> {
        Ok(Self {
            signature: CompiledSignature::from_config(config),
            regex: Regex::new(&config.pattern)
                .with_context(|| format!("failed to compile ips signature '{}'", config.id))?,
        })
    }
}

fn build_automaton(patterns: &[Vec<u8>], case_insensitive: bool) -> Result<Option<AhoCorasick>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    AhoCorasickBuilder::new()
        .ascii_case_insensitive(case_insensitive)
        .build(patterns)
        .map(Some)
        .context("failed to build ips aho-corasick automaton")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use etherparse::PacketBuilder;

    use super::*;
    use crate::data_plane::ips::config::{
        IpsDetectionConfig, IpsGeneralConfig, IpsMatchType, IpsPatternEncoding,
    };
    
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
                    match_type: IpsMatchType::Regex,
                    pattern_encoding: IpsPatternEncoding::Text,
                    case_insensitive: false,
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
                    match_type: IpsMatchType::Regex,
                    pattern_encoding: IpsPatternEncoding::Text,
                    case_insensitive: false,
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
            Some(DpiContext {
                app_proto: Some(AppProto::Http),
                ..Default::default()
            }),
        )
        .expect("packet context should parse")
    }

    #[test]
    fn block_signature_halts_packet() {
        let ips = Ips::new(make_config()).expect("ips should initialize");
        let ctx = build_tcp_packet(b"GET /?q=UNION SELECT 1 HTTP/1.1\r\nHost: x\r\n\r\n", 80);

        let verdict = ips.inspect_packet(&ctx);
        assert!(matches!(verdict, IpsVerdict::Block(matched) if matched.name == "SQLi"));
    }

    #[test]
    fn alert_signature_warns_without_block() {
        let ips = Ips::new(make_config()).expect("ips should initialize");
        let ctx = build_tcp_packet(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0.1\r\n\r\n",
            8080,
        );

        let verdict = ips.inspect_packet(&ctx);
        assert!(matches!(verdict, IpsVerdict::Alert(matches) if matches.iter().any(|matched| matched.name == "Curl UA")));
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
    fn literal_signature_uses_aho_corasick() {
        let mut config = make_config();
        config.signatures[0].pattern = "UNION SELECT".into();
        config.signatures[0].match_type = IpsMatchType::Literal;
        config.signatures[0].case_insensitive = true;
        let ips = Ips::new(config).expect("ips should initialize");
        let ctx = build_tcp_packet(b"GET /?q=union select 1 HTTP/1.1\r\nHost: x\r\n\r\n", 80);

        let verdict = ips.inspect_packet(&ctx);
        assert!(matches!(verdict, IpsVerdict::Block(matched) if matched.id == "http-sqli"));
    }

    #[test]
    fn hex_literal_signature_matches_bytes() {
        let mut config = make_config();
        config.signatures[0].pattern = "90909090".into();
        config.signatures[0].match_type = IpsMatchType::Literal;
        config.signatures[0].pattern_encoding = IpsPatternEncoding::Hex;
        config.signatures[0].case_insensitive = false;
        config.signatures[0].app_protocols.clear();
        config.signatures[0].dst_ports.clear();
        let ips = Ips::new(config).expect("ips should initialize");
        let ctx = build_tcp_packet(b"\x90\x90\x90\x90/bin/sh", 4444);

        let verdict = ips.inspect_packet(&ctx);
        assert!(matches!(verdict, IpsVerdict::Block(matched) if matched.id == "http-sqli"));
    }

    #[test]
    fn global_disable_skips_detection() {
        let mut config = make_config();
        config.general.enabled = false;
        let ips = Ips::new(config).expect("ips should initialize");
        let ctx = build_tcp_packet(b"GET /?q=UNION SELECT 1 HTTP/1.1\r\nHost: x\r\n\r\n", 80);

        assert_eq!(ips.inspect_packet(&ctx), IpsVerdict::Allow);
    }
}
