use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::proto::config as proto;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DnsInspectionConfig {
    pub general: DnsInspectionGeneralConfig,
    pub blocklist: DnsInspectionBlocklistConfig,
    pub dns_tunneling: DnsInspectionDnsTunnelingConfig,
    pub dnssec: DnsInspectionDnssecConfig,
}

impl Default for DnsInspectionConfig {
    fn default() -> Self {
        Self {
            general: DnsInspectionGeneralConfig::default(),
            blocklist: DnsInspectionBlocklistConfig::default(),
            dns_tunneling: DnsInspectionDnsTunnelingConfig::default(),
            dnssec: DnsInspectionDnssecConfig::default(),
        }
    }
}

impl DnsInspectionConfig {
    pub fn to_proto(&self) -> proto::DnsInspectionConfig {
        proto::DnsInspectionConfig {
            general: Some(self.general.to_proto()),
            blocklist: Some(self.blocklist.to_proto()),
            dns_tunneling: Some(self.dns_tunneling.to_proto()),
            dnssec: Some(self.dnssec.to_proto()),
        }
    }

    pub fn from_proto(proto_config: proto::DnsInspectionConfig) -> Result<Self> {
        Ok(Self {
            general: DnsInspectionGeneralConfig::from_proto(proto_config.general.unwrap_or_default()),
            blocklist: DnsInspectionBlocklistConfig::from_proto(proto_config.blocklist.unwrap_or_default()),
            dns_tunneling: DnsInspectionDnsTunnelingConfig::from_proto(
                proto_config.dns_tunneling.unwrap_or_default(),
            )?,
            dnssec: DnsInspectionDnssecConfig::from_proto(proto_config.dnssec.unwrap_or_default())?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsInspectionGeneralConfig {
    pub enabled: bool,
}

impl Default for DnsInspectionGeneralConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

impl DnsInspectionGeneralConfig {
    fn to_proto(&self) -> proto::DnsInspectionGeneralConfig {
        proto::DnsInspectionGeneralConfig {
            enabled: self.enabled,
        }
    }

    fn from_proto(proto_config: proto::DnsInspectionGeneralConfig) -> Self {
        Self {
            enabled: proto_config.enabled,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsInspectionBlocklistConfig {
    pub enabled: bool,
    pub domains: Vec<String>,
}

impl Default for DnsInspectionBlocklistConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
        }
    }
}

impl DnsInspectionBlocklistConfig {
    fn to_proto(&self) -> proto::DnsInspectionBlocklistConfig {
        proto::DnsInspectionBlocklistConfig {
            enabled: self.enabled,
            domains: self.domains.clone(),
        }
    }

    fn from_proto(proto_config: proto::DnsInspectionBlocklistConfig) -> Self {
        Self {
            enabled: proto_config.enabled,
            domains: proto_config.domains,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DnsInspectionDnsTunnelingConfig {
    pub enabled: bool,
    pub max_label_length: usize,
    pub entropy_threshold: f32,
    #[serde(with = "duration_seconds")]
    pub window_seconds: Duration,
    pub max_queries_per_domain: usize,
    pub max_unique_subdomains: usize,
    /// Lista domen ignorowanych przez detektor tunelowania. Obsługuje wildcard (np. `*.example.com`).
    pub ignore_domains: Vec<String>,
    /// Znormalizowany próg score (0.0–1.0). Score >= próg → werdykt Alert.
    pub alert_threshold: f32,
    /// Znormalizowany próg score (0.0–1.0). Score >= próg → werdykt Block.
    pub block_threshold: f32,
}

impl Default for DnsInspectionDnsTunnelingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_label_length: 40,
            entropy_threshold: 3.5,
            window_seconds: Duration::from_secs(60),
            max_queries_per_domain: 100,
            max_unique_subdomains: 20,
            ignore_domains: Vec::new(),
            alert_threshold: 0.6,
            block_threshold: 0.85,
        }
    }
}

impl DnsInspectionDnsTunnelingConfig {
    pub(crate) fn to_proto(&self) -> proto::DnsInspectionDnsTunnelingConfig {
        proto::DnsInspectionDnsTunnelingConfig {
            enabled: self.enabled,
            max_label_length: self.max_label_length as u32,
            entropy_threshold: self.entropy_threshold,
            window_seconds: duration_secs_u32(self.window_seconds),
            max_queries_per_domain: self.max_queries_per_domain as u32,
            max_unique_subdomains: self.max_unique_subdomains as u32,
            ignore_domains: self.ignore_domains.clone(),
            alert_threshold: self.alert_threshold,
            block_threshold: self.block_threshold,
        }
    }

    pub(crate) fn from_proto(proto_config: proto::DnsInspectionDnsTunnelingConfig) -> Result<Self> {
        Ok(Self {
            enabled: proto_config.enabled,
            max_label_length: usize::try_from(proto_config.max_label_length)
                .context("dns_tunneling.max_label_length does not fit into usize")?,
            entropy_threshold: proto_config.entropy_threshold,
            window_seconds: Duration::from_secs(u64::from(proto_config.window_seconds)),
            max_queries_per_domain: usize::try_from(proto_config.max_queries_per_domain)
                .context("dns_tunneling.max_queries_per_domain does not fit into usize")?,
            max_unique_subdomains: usize::try_from(proto_config.max_unique_subdomains)
                .context("dns_tunneling.max_unique_subdomains does not fit into usize")?,
            ignore_domains: proto_config.ignore_domains,
            alert_threshold: proto_config.alert_threshold,
            block_threshold: proto_config.block_threshold,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DnsInspectionDnssecConfig {
    pub enabled: bool,
    pub max_lookups_per_packet: usize,
    pub default_on_resolver_failure: DnsInspectionDnssecFailureAction,
    pub resolver: DnsInspectionDnssecResolverConfig,
    pub cache: DnsInspectionDnssecCacheConfig,
}

impl Default for DnsInspectionDnssecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_lookups_per_packet: 1,
            default_on_resolver_failure: DnsInspectionDnssecFailureAction::default(),
            resolver: DnsInspectionDnssecResolverConfig::default(),
            cache: DnsInspectionDnssecCacheConfig::default(),
        }
    }
}

impl DnsInspectionDnssecConfig {
    fn to_proto(&self) -> proto::DnsInspectionDnssecConfig {
        proto::DnsInspectionDnssecConfig {
            enabled: self.enabled,
            max_lookups_per_packet: self.max_lookups_per_packet as u32,
            default_on_resolver_failure: self.default_on_resolver_failure.to_proto() as i32,
            resolver: Some(self.resolver.to_proto()),
            cache: Some(self.cache.to_proto()),
        }
    }

    fn from_proto(proto_config: proto::DnsInspectionDnssecConfig) -> Result<Self> {
        Ok(Self {
            enabled: proto_config.enabled,
            max_lookups_per_packet: usize::try_from(proto_config.max_lookups_per_packet)
                .context("dnssec.max_lookups_per_packet does not fit into usize")?,
            default_on_resolver_failure: DnsInspectionDnssecFailureAction::from_proto(
                proto_config.default_on_resolver_failure,
            )?,
            resolver: DnsInspectionDnssecResolverConfig::from_proto(proto_config.resolver.unwrap_or_default())?,
            cache: DnsInspectionDnssecCacheConfig::from_proto(proto_config.cache.unwrap_or_default())?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsInspectionDnssecResolverConfig {
    pub primary: DnsInspectionDnssecResolverEndpoint,
    pub secondary: Option<DnsInspectionDnssecResolverEndpoint>,
    pub transport: DnsInspectionDnssecTransport,
    #[serde(with = "duration_millis")]
    pub timeout_ms: Duration,
    pub retries: u8,
}

impl Default for DnsInspectionDnssecResolverConfig {
    fn default() -> Self {
        Self {
            primary: DnsInspectionDnssecResolverEndpoint::default(),
            secondary: None,
            transport: DnsInspectionDnssecTransport::default(),
            timeout_ms: Duration::from_millis(2000),
            retries: 1,
        }
    }
}

impl DnsInspectionDnssecResolverConfig {
    fn to_proto(&self) -> proto::DnsInspectionDnssecResolverConfig {
        proto::DnsInspectionDnssecResolverConfig {
            primary: Some(self.primary.to_proto()),
            secondary: self.secondary.as_ref().map(DnsInspectionDnssecResolverEndpoint::to_proto),
            transport: self.transport.to_proto() as i32,
            timeout_ms: duration_millis_u32(self.timeout_ms),
            retries: u32::from(self.retries),
        }
    }

    fn from_proto(proto_config: proto::DnsInspectionDnssecResolverConfig) -> Result<Self> {
        Ok(Self {
            primary: DnsInspectionDnssecResolverEndpoint::from_proto(proto_config.primary.unwrap_or_default())?,
            secondary: proto_config
                .secondary
                .map(DnsInspectionDnssecResolverEndpoint::from_proto)
                .transpose()?,
            transport: DnsInspectionDnssecTransport::from_proto(proto_config.transport)?,
            timeout_ms: Duration::from_millis(u64::from(proto_config.timeout_ms)),
            retries: u8::try_from(proto_config.retries)
                .context("dnssec.resolver.retries must fit into u8")?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsInspectionDnssecResolverEndpoint {
    pub address: String,
    pub port: u16,
}

impl Default for DnsInspectionDnssecResolverEndpoint {
    fn default() -> Self {
        Self {
            address: "127.0.0.1".into(),
            port: 53,
        }
    }
}

impl DnsInspectionDnssecResolverEndpoint {
    fn to_proto(&self) -> proto::DnsInspectionDnssecResolverEndpoint {
        proto::DnsInspectionDnssecResolverEndpoint {
            address: self.address.clone(),
            port: u32::from(self.port),
        }
    }

    fn from_proto(proto_config: proto::DnsInspectionDnssecResolverEndpoint) -> Result<Self> {
        Ok(Self {
            address: proto_config.address,
            port: u16::try_from(proto_config.port)
                .context("dnssec.resolver endpoint port must fit into u16")?,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsInspectionDnssecTransport {
    Udp,
    Tcp,
    #[default]
    UdpWithTcpFallback,
}

impl DnsInspectionDnssecTransport {
    fn to_proto(self) -> proto::DnsInspectionDnssecTransport {
        match self {
            Self::Udp => proto::DnsInspectionDnssecTransport::Udp,
            Self::Tcp => proto::DnsInspectionDnssecTransport::Tcp,
            Self::UdpWithTcpFallback => proto::DnsInspectionDnssecTransport::UdpWithTcpFallback,
        }
    }

    fn from_proto(value: i32) -> Result<Self> {
        let transport = proto::DnsInspectionDnssecTransport::try_from(value)
            .map_err(|_| anyhow::anyhow!("invalid dnssec transport enum value: {value}"))?;

        Ok(match transport {
            proto::DnsInspectionDnssecTransport::Unspecified => Self::default(),
            proto::DnsInspectionDnssecTransport::Udp => Self::Udp,
            proto::DnsInspectionDnssecTransport::Tcp => Self::Tcp,
            proto::DnsInspectionDnssecTransport::UdpWithTcpFallback => Self::UdpWithTcpFallback,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsInspectionDnssecFailureAction {
    #[default]
    Allow,
    Alert,
    Block,
}

impl DnsInspectionDnssecFailureAction {
    fn to_proto(self) -> proto::DnsInspectionDnssecFailureAction {
        match self {
            Self::Allow => proto::DnsInspectionDnssecFailureAction::Allow,
            Self::Alert => proto::DnsInspectionDnssecFailureAction::Alert,
            Self::Block => proto::DnsInspectionDnssecFailureAction::Block,
        }
    }

    fn from_proto(value: i32) -> Result<Self> {
        let action = proto::DnsInspectionDnssecFailureAction::try_from(value)
            .map_err(|_| anyhow::anyhow!("invalid dnssec failure action enum value: {value}"))?;

        Ok(match action {
            proto::DnsInspectionDnssecFailureAction::Unspecified => Self::default(),
            proto::DnsInspectionDnssecFailureAction::Allow => Self::Allow,
            proto::DnsInspectionDnssecFailureAction::Alert => Self::Alert,
            proto::DnsInspectionDnssecFailureAction::Block => Self::Block,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DnsInspectionDnssecCacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub ttl_seconds: DnsInspectionDnssecCacheTtlConfig,
}

impl Default for DnsInspectionDnssecCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 4096,
            ttl_seconds: DnsInspectionDnssecCacheTtlConfig::default(),
        }
    }
}

impl DnsInspectionDnssecCacheConfig {
    fn to_proto(&self) -> proto::DnsInspectionDnssecCacheConfig {
        proto::DnsInspectionDnssecCacheConfig {
            enabled: self.enabled,
            max_entries: self.max_entries as u32,
            ttl_seconds: Some(self.ttl_seconds.to_proto()),
        }
    }

    fn from_proto(proto_config: proto::DnsInspectionDnssecCacheConfig) -> Result<Self> {
        Ok(Self {
            enabled: proto_config.enabled,
            max_entries: usize::try_from(proto_config.max_entries)
                .context("dnssec.cache.max_entries does not fit into usize")?,
            ttl_seconds: DnsInspectionDnssecCacheTtlConfig::from_proto(
                proto_config.ttl_seconds.unwrap_or_default(),
            ),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsInspectionDnssecCacheTtlConfig {
    #[serde(with = "duration_seconds")]
    pub secure: Duration,
    #[serde(with = "duration_seconds")]
    pub insecure: Duration,
    #[serde(with = "duration_seconds")]
    pub bogus: Duration,
    #[serde(with = "duration_seconds")]
    pub failure: Duration,
}

impl Default for DnsInspectionDnssecCacheTtlConfig {
    fn default() -> Self {
        Self {
            secure: Duration::from_secs(300),
            insecure: Duration::from_secs(300),
            bogus: Duration::from_secs(60),
            failure: Duration::from_secs(15),
        }
    }
}

impl DnsInspectionDnssecCacheTtlConfig {
    fn to_proto(&self) -> proto::DnsInspectionDnssecCacheTtlConfig {
        proto::DnsInspectionDnssecCacheTtlConfig {
            secure: duration_secs_u32(self.secure),
            insecure: duration_secs_u32(self.insecure),
            bogus: duration_secs_u32(self.bogus),
            failure: duration_secs_u32(self.failure),
        }
    }

    fn from_proto(proto_config: proto::DnsInspectionDnssecCacheTtlConfig) -> Self {
        Self {
            secure: Duration::from_secs(u64::from(proto_config.secure)),
            insecure: Duration::from_secs(u64::from(proto_config.insecure)),
            bogus: Duration::from_secs(u64::from(proto_config.bogus)),
            failure: Duration::from_secs(u64::from(proto_config.failure)),
        }
    }
}

fn duration_secs_u32(duration: Duration) -> u32 {
    duration.as_secs().min(u64::from(u32::MAX)) as u32
}

fn duration_millis_u32(duration: Duration) -> u32 {
    duration.as_millis().min(u128::from(u32::MAX)) as u32
}

mod duration_seconds {
    use super::*;

    pub fn serialize<S>(value: &Duration, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer,
    {
        serializer.serialize_u64(value.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
    where D: Deserializer<'de>,
    {
        let seconds = u64::deserialize(deserializer)?;
        
        Ok(Duration::from_secs(seconds))
    }
}

mod duration_millis {
    use super::*;

    pub fn serialize<S>(value: &Duration, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer,
    {
        serializer.serialize_u64(value.as_millis().min(u128::from(u64::MAX)) as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
    where D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}
