use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use anyhow::{Context, Result, anyhow, bail};

use crate::dpi::AppProto;
use crate::proto::{common, config as proto};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct IpsConfig {
    pub general: IpsGeneralConfig,
    pub detection: IpsDetectionConfig,
    pub signatures: Vec<IpsSignatureConfig>,
}

impl Default for IpsConfig {
    fn default() -> Self {
        Self {
            general: IpsGeneralConfig::default(),
            detection: IpsDetectionConfig::default(),
            signatures: Vec::new(),
        }
    }
}

impl IpsConfig {
    pub fn to_proto(&self) -> proto::IpsConfig {
        proto::IpsConfig {
            general: Some(self.general.to_proto()),
            detection: Some(self.detection.to_proto()),
            signatures: self
                .signatures
                .iter()
                .map(IpsSignatureConfig::to_proto)
                .collect(),
        }
    }

    pub fn from_proto(proto_config: proto::IpsConfig) -> Result<Self> {
        Ok(Self {
            general: IpsGeneralConfig::from_proto(proto_config.general.unwrap_or_default()),
            detection: IpsDetectionConfig::from_proto(proto_config.detection.unwrap_or_default())?,
            signatures: proto_config
                .signatures
                .into_iter()
                .map(IpsSignatureConfig::from_proto)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct IpsGeneralConfig {
    pub enabled: bool,
}

impl Default for IpsGeneralConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

impl IpsGeneralConfig {
    fn to_proto(&self) -> proto::IpsGeneralConfig {
        proto::IpsGeneralConfig {
            enabled: self.enabled,
        }
    }

    fn from_proto(proto_config: proto::IpsGeneralConfig) -> Self {
        Self {
            enabled: proto_config.enabled,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct IpsDetectionConfig {
    pub enabled: bool,
    pub max_payload_bytes: usize,
    pub max_matches_per_packet: usize,
}

impl Default for IpsDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_payload_bytes: 4096,
            max_matches_per_packet: 8,
        }
    }
}

impl IpsDetectionConfig {
    fn to_proto(&self) -> proto::IpsDetectionConfig {
        proto::IpsDetectionConfig {
            enabled: self.enabled,
            max_payload_bytes: self.max_payload_bytes as u32,
            max_matches_per_packet: self.max_matches_per_packet as u32,
        }
    }

    fn from_proto(proto_config: proto::IpsDetectionConfig) -> Result<Self> {
        let defaults = Self::default();
        let max_payload_bytes = if proto_config.max_payload_bytes == 0 {
            defaults.max_payload_bytes
        } else {
            usize::try_from(proto_config.max_payload_bytes)
                .context("ips.detection.max_payload_bytes does not fit into usize")?
        };
        let max_matches_per_packet = if proto_config.max_matches_per_packet == 0 {
            defaults.max_matches_per_packet
        } else {
            usize::try_from(proto_config.max_matches_per_packet)
                .context("ips.detection.max_matches_per_packet does not fit into usize")?
        };

        Ok(Self {
            enabled: proto_config.enabled,
            max_payload_bytes,
            max_matches_per_packet,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct IpsSignatureConfig {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub category: String,
    pub pattern: String,
    pub match_type: IpsMatchType,
    pub pattern_encoding: IpsPatternEncoding,
    pub case_insensitive: bool,
    pub severity: IpsSeverity,
    pub action: IpsAction,
    pub app_protocols: Vec<IpsAppProtocol>,
    pub src_ports: Vec<u16>,
    pub dst_ports: Vec<u16>,
}

impl Default for IpsSignatureConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: false,
            category: "other".to_string(),
            pattern: String::new(),
            match_type: IpsMatchType::default(),
            pattern_encoding: IpsPatternEncoding::default(),
            case_insensitive: false,
            severity: IpsSeverity::default(),
            action: IpsAction::default(),
            app_protocols: Vec::new(),
            src_ports: Vec::new(),
            dst_ports: Vec::new(),
        }
    }
}

impl IpsSignatureConfig {
    fn to_proto(&self) -> proto::IpsSignatureConfig {
        proto::IpsSignatureConfig {
            id: self.id.clone(),
            name: self.name.clone(),
            enabled: self.enabled,
            category: self.category.clone(),
            pattern: self.pattern.clone(),
            match_type: self.match_type.to_proto() as i32,
            pattern_encoding: self.pattern_encoding.to_proto() as i32,
            case_insensitive: self.case_insensitive,
            severity: self.severity.to_proto() as i32,
            action: self.action.to_proto() as i32,
            app_protocols: self
                .app_protocols
                .iter()
                .map(|proto| proto.to_proto() as i32)
                .collect(),
            src_ports: self.src_ports.iter().map(|port| u32::from(*port)).collect(),
            dst_ports: self.dst_ports.iter().map(|port| u32::from(*port)).collect(),
        }
    }

    fn from_proto(proto_config: proto::IpsSignatureConfig) -> Result<Self> {
        if proto_config.id.trim().is_empty() {
            bail!("ips signature id must not be empty");
        }
        if proto_config.name.trim().is_empty() {
            bail!("ips signature name must not be empty");
        }
        if proto_config.pattern.trim().is_empty() {
            bail!("ips signature pattern must not be empty");
        }

        let match_type = IpsMatchType::from_proto(proto_config.match_type)?;
        let pattern_encoding = IpsPatternEncoding::from_proto(proto_config.pattern_encoding)?;

        if pattern_encoding == IpsPatternEncoding::Hex && match_type == IpsMatchType::Regex {
            bail!("ips signature '{}' cannot use hex encoding with regex match type", proto_config.id);
        }
        if pattern_encoding == IpsPatternEncoding::Hex && proto_config.case_insensitive {
            bail!("ips signature '{}' cannot use case_insensitive with hex encoding", proto_config.id);
        }

        match match_type {
            IpsMatchType::Literal => {
                decode_literal_pattern(&proto_config.pattern, pattern_encoding).with_context(|| {
                    format!("ips signature '{}' has invalid literal pattern", proto_config.id)
                })?;
            }
            IpsMatchType::Regex => {
                Regex::new(&proto_config.pattern).with_context(|| {
                    format!(
                        "ips signature '{}' has invalid regex pattern",
                        proto_config.id
                    )
                })?;
            }
        }

        let src_ports = proto_config
            .src_ports
            .into_iter()
            .map(parse_port)
            .collect::<Result<Vec<_>>>()?;
        let dst_ports = proto_config
            .dst_ports
            .into_iter()
            .map(parse_port)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            id: proto_config.id,
            name: proto_config.name,
            enabled: proto_config.enabled,
            category: normalize_category(proto_config.category),
            pattern: proto_config.pattern,
            match_type,
            pattern_encoding,
            case_insensitive: proto_config.case_insensitive,
            severity: IpsSeverity::from_proto(proto_config.severity)?,
            action: IpsAction::from_proto(proto_config.action)?,
            app_protocols: proto_config
                .app_protocols
                .into_iter()
                .map(IpsAppProtocol::from_proto)
                .collect::<Result<Vec<_>>>()?,
            src_ports,
            dst_ports,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpsMatchType {
    Literal,
    #[default]
    Regex,
}

impl IpsMatchType {
    fn to_proto(self) -> proto::IpsMatchType {
        match self {
            Self::Literal => proto::IpsMatchType::Literal,
            Self::Regex => proto::IpsMatchType::Regex,
        }
    }

    fn from_proto(value: i32) -> Result<Self> {
        let match_type = proto::IpsMatchType::try_from(value)
            .map_err(|_| anyhow!("invalid ips match type value: {value}"))?;

        Ok(match match_type {
            proto::IpsMatchType::Unspecified => Self::default(),
            proto::IpsMatchType::Literal => Self::Literal,
            proto::IpsMatchType::Regex => Self::Regex,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpsPatternEncoding {
    #[default]
    Text,
    Hex,
}

impl IpsPatternEncoding {
    fn to_proto(self) -> proto::IpsPatternEncoding {
        match self {
            Self::Text => proto::IpsPatternEncoding::Text,
            Self::Hex => proto::IpsPatternEncoding::Hex,
        }
    }

    fn from_proto(value: i32) -> Result<Self> {
        let encoding = proto::IpsPatternEncoding::try_from(value)
            .map_err(|_| anyhow!("invalid ips pattern encoding value: {value}"))?;

        Ok(match encoding {
            proto::IpsPatternEncoding::Unspecified => Self::default(),
            proto::IpsPatternEncoding::Text => Self::Text,
            proto::IpsPatternEncoding::Hex => Self::Hex,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpsSeverity {
    Info,
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl IpsSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    fn to_proto(self) -> common::Severity {
        match self {
            Self::Info => common::Severity::Info,
            Self::Low => common::Severity::Low,
            Self::Medium => common::Severity::Medium,
            Self::High => common::Severity::High,
            Self::Critical => common::Severity::Critical,
        }
    }

    fn from_proto(value: i32) -> Result<Self> {
        let severity = common::Severity::try_from(value)
            .map_err(|_| anyhow!("invalid ips severity value: {value}"))?;

        Ok(match severity {
            common::Severity::Unspecified => Self::default(),
            common::Severity::Info => Self::Info,
            common::Severity::Low => Self::Low,
            common::Severity::Medium => Self::Medium,
            common::Severity::High => Self::High,
            common::Severity::Critical => Self::Critical,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpsAction {
    #[default]
    Alert,
    Block,
}

impl IpsAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Block => "block",
        }
    }

    fn to_proto(self) -> proto::IpsAction {
        match self {
            Self::Alert => proto::IpsAction::Alert,
            Self::Block => proto::IpsAction::Block,
        }
    }

    fn from_proto(value: i32) -> Result<Self> {
        let action = proto::IpsAction::try_from(value)
            .map_err(|_| anyhow!("invalid ips action value: {value}"))?;

        Ok(match action {
            proto::IpsAction::Unspecified | proto::IpsAction::Alert => Self::Alert,
            proto::IpsAction::Block => Self::Block,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IpsAppProtocol {
    Http,
    Tls,
    Dns,
    Ssh,
    Ftp,
    Smtp,
    Rdp,
    Smb,
    Quic,
    Unknown,
}

impl IpsAppProtocol {
    pub fn matches(self, proto: AppProto) -> bool {
        matches!(
            (self, proto),
            (Self::Http, AppProto::Http)
                | (Self::Tls, AppProto::Tls)
                | (Self::Dns, AppProto::Dns)
                | (Self::Ssh, AppProto::Ssh)
                | (Self::Ftp, AppProto::Ftp)
                | (Self::Smtp, AppProto::Smtp)
                | (Self::Rdp, AppProto::Rdp)
                | (Self::Smb, AppProto::Smb)
                | (Self::Quic, AppProto::Quic)
                | (Self::Unknown, AppProto::Unknown)
        )
    }

    fn to_proto(self) -> proto::IpsAppProtocol {
        match self {
            Self::Http => proto::IpsAppProtocol::Http,
            Self::Tls => proto::IpsAppProtocol::Tls,
            Self::Dns => proto::IpsAppProtocol::Dns,
            Self::Ssh => proto::IpsAppProtocol::Ssh,
            Self::Ftp => proto::IpsAppProtocol::Ftp,
            Self::Smtp => proto::IpsAppProtocol::Smtp,
            Self::Rdp => proto::IpsAppProtocol::Rdp,
            Self::Smb => proto::IpsAppProtocol::Smb,
            Self::Quic => proto::IpsAppProtocol::Quic,
            Self::Unknown => proto::IpsAppProtocol::Unknown,
        }
    }

    fn from_proto(value: i32) -> Result<Self> {
        let protocol = proto::IpsAppProtocol::try_from(value)
            .map_err(|_| anyhow!("invalid ips app protocol value: {value}"))?;

        Ok(match protocol {
            proto::IpsAppProtocol::Http => Self::Http,
            proto::IpsAppProtocol::Tls => Self::Tls,
            proto::IpsAppProtocol::Dns => Self::Dns,
            proto::IpsAppProtocol::Ssh => Self::Ssh,
            proto::IpsAppProtocol::Ftp => Self::Ftp,
            proto::IpsAppProtocol::Smtp => Self::Smtp,
            proto::IpsAppProtocol::Rdp => Self::Rdp,
            proto::IpsAppProtocol::Smb => Self::Smb,
            proto::IpsAppProtocol::Quic => Self::Quic,
            proto::IpsAppProtocol::Unknown => Self::Unknown,
            proto::IpsAppProtocol::Unspecified => {
                bail!("ips app protocol filter must not contain unspecified");
            }
        })
    }
}

fn parse_port(value: u32) -> Result<u16> {
    let port = u16::try_from(value).context("ips port filter does not fit into u16")?;
    if port == 0 {
        bail!("ips port filter must be greater than zero");
    }
    Ok(port)
}

fn normalize_category(category: String) -> String {
    let trimmed = category.trim();
    if trimmed.is_empty() {
        "other".to_string()
    } else {
        trimmed.to_lowercase()
    }
}

pub fn decode_literal_pattern(pattern: &str, encoding: IpsPatternEncoding) -> Result<Vec<u8>> {
    match encoding {
        IpsPatternEncoding::Text => Ok(pattern.as_bytes().to_vec()),
        IpsPatternEncoding::Hex => decode_hex_pattern(pattern),
    }
}

fn decode_hex_pattern(pattern: &str) -> Result<Vec<u8>> {
    let compact = pattern
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();

    if compact.is_empty() {
        bail!("hex pattern must not be empty");
    }
    if compact.len() % 2 != 0 {
        bail!("hex pattern must contain an even number of digits");
    }

    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let pair = std::str::from_utf8(chunk).context("hex pattern is not valid utf-8")?;
            u8::from_str_radix(pair, 16).with_context(|| format!("invalid hex byte '{pair}'"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_roundtrip_keeps_signature_filters() {
        let config = IpsConfig {
            general: IpsGeneralConfig { enabled: true },
            detection: IpsDetectionConfig {
                enabled: true,
                max_payload_bytes: 1024,
                max_matches_per_packet: 2,
            },
            signatures: vec![IpsSignatureConfig {
                id: "sig-1".into(),
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
                src_ports: vec![12345],
                dst_ports: vec![80, 8080],
            }],
        };

        let roundtrip = IpsConfig::from_proto(config.to_proto()).expect("config should roundtrip");
        assert_eq!(roundtrip, config);
    }

    #[test]
    fn from_proto_rejects_invalid_regex() {
        let err = IpsConfig::from_proto(proto::IpsConfig {
            general: Some(proto::IpsGeneralConfig { enabled: true }),
            detection: Some(proto::IpsDetectionConfig {
                enabled: true,
                max_payload_bytes: 1024,
                max_matches_per_packet: 1,
            }),
            signatures: vec![proto::IpsSignatureConfig {
                id: "sig-1".into(),
                name: "broken".into(),
                enabled: true,
                category: "other".into(),
                pattern: "(".into(),
                match_type: proto::IpsMatchType::Regex as i32,
                pattern_encoding: proto::IpsPatternEncoding::Text as i32,
                case_insensitive: false,
                severity: common::Severity::High as i32,
                action: proto::IpsAction::Block as i32,
                app_protocols: vec![],
                src_ports: vec![],
                dst_ports: vec![],
            }],
        })
        .expect_err("invalid regex should be rejected");

        assert!(err.to_string().contains("invalid regex"));
    }

    #[test]
    fn zero_detection_limits_fall_back_to_defaults() {
        let config = IpsConfig::from_proto(proto::IpsConfig {
            general: Some(proto::IpsGeneralConfig { enabled: true }),
            detection: Some(proto::IpsDetectionConfig {
                enabled: true,
                max_payload_bytes: 0,
                max_matches_per_packet: 0,
            }),
            signatures: vec![],
        })
        .expect("zero values should be normalized");

        assert_eq!(
            config.detection.max_payload_bytes,
            IpsDetectionConfig::default().max_payload_bytes
        );
        assert_eq!(
            config.detection.max_matches_per_packet,
            IpsDetectionConfig::default().max_matches_per_packet
        );
    }

    #[test]
    fn literal_hex_pattern_decodes_bytes() {
        let decoded = decode_literal_pattern("90 90 2f 73", IpsPatternEncoding::Hex)
            .expect("hex should decode");

        assert_eq!(decoded, vec![0x90, 0x90, 0x2f, 0x73]);
    }

    #[test]
    fn invalid_hex_pattern_is_rejected() {
        let err = decode_literal_pattern("909", IpsPatternEncoding::Hex)
            .expect_err("odd hex length should fail");

        assert!(err.to_string().contains("even number"));
    }
}
