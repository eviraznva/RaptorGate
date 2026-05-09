use std::time::Duration;
use serde::{Deserialize, Serialize};

use crate::conntrack::tuple::Protocol;
use crate::conntrack::reassembler::ReassemblyConfig;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConntrackConfig {
    #[serde(default = "default_max_entries")]
    pub max_entries: u32,

    #[serde(default = "default_htable_size")]
    pub htable_size: u32,

    #[serde(default = "default_gc_interval", with = "duration_secs")]
    pub gc_interval: Duration,

    #[serde(default = "default_log_invalid")]
    pub log_invalid: LogInvalid,

    #[serde(default)]
    pub accounting: bool,

    #[serde(default)]
    pub timestamp: bool,

    #[serde(default = "default_events_enabled")]
    pub events_enabled: bool,

    #[serde(default)]
    pub tcp: TcpConfig,

    #[serde(default)]
    pub udp: UdpConfig,

    #[serde(default)]
    pub icmp: IcmpConfig,

    #[serde(default = "default_generic_timeout", with = "duration_secs")]
    pub generic_timeout: Duration,

    #[serde(default)]
    pub reassembly: ReassemblyConfig,
}

impl ConntrackConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_entries < 1024 {
            return Err(ConfigError::TooSmall {
                field: "max_entries",
                value: self.max_entries as u64,
                min: 1024
            })
        }

        if self.htable_size > self.max_entries {
            return Err(ConfigError::Inconsistent(
                "htable_size cannot exceed max_entries".into(),
            ));
        }

        if self.tcp.timeout.established < self.tcp.timeout.fin_wait {
            return Err(ConfigError::Inconsistent(
                "tcp.timeout.established must be >= fin_wait".into(),
            ));
        }

        if self.gc_interval < Duration::from_millis(500) {
            return Err(ConfigError::TooSmall {
                field: "gc_interval",
                value: self.gc_interval.as_millis() as u64,
                min: 500,
            });
        }

        if self.reassembly.max_buffered_bytes < 4096 {
            return Err(ConfigError::TooSmall {
                field: "reassembly.max_buffered_bytes",
                value: self.reassembly.max_buffered_bytes as u64,
                min: 4096,
            });
        }
        
        Ok(())
    }

    pub fn timeout_for(&self, proto: Protocol) -> Duration {
        match proto {
            Protocol::Tcp => self.tcp.timeout.established,
            Protocol::Udp => self.udp.timeout,
            Protocol::Icmp | Protocol::IcmpV6 => self.icmp.timeout,
        }
    }
}

impl Default for ConntrackConfig {
    fn default() -> Self {
        Self {
            max_entries: default_max_entries(),
            htable_size: default_htable_size(),
            gc_interval: default_gc_interval(),
            log_invalid: default_log_invalid(),
            accounting: false,
            timestamp: false,
            events_enabled: default_events_enabled(),
            tcp: TcpConfig::default(),
            udp: UdpConfig::default(),
            icmp: IcmpConfig::default(),
            generic_timeout: default_generic_timeout(),
            reassembly: ReassemblyConfig::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{field} = {value} is below minimum {min}")]
    TooSmall { field: &'static str, value: u64, min: u64 },

    #[error("{0}")]
    Inconsistent(String),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogInvalid {
    None,
    All,
    Tcp,
    Udp,
    Icmp
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpConfig {
    #[serde(default = "default_true")]
    pub loose: bool, // Pozwala śledzić TCP flow który już istniał przed startem firewalla, bez tego restart firewalla zerwałby wszystkie sesje

    #[serde(default)]
    pub be_liberal: bool, // Pakiety out-of-window nie są oznaczane jako INVALID tylko logowane. Domyślnie false

    #[serde(default)]
    pub ignore_invalid_rst: bool, // RST z błędną sekwencją domyślnie INVALID. Gdy true ignoruje. Niektórzy dostawcy wysyłają złe RST-y. Domyślnie false

    #[serde(default = "default_max_retrans")]
    pub max_retrans: u8, // Ile retransmisji TCP jednego pakietu zanim entry przejdzie do MAX_RETRANS. Domyślnie 3

    #[serde(default)]
    pub timeout: TcpTimeouts,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            loose: true,
            be_liberal: false,
            ignore_invalid_rst: false,
            max_retrans: default_max_retrans(),
            timeout: TcpTimeouts::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpTimeouts {
    #[serde(default = "tcp_t_syn_sent", with = "duration_secs")]
    pub syn_sent: Duration, // Domyślnie 120s

    #[serde(default = "tcp_t_syn_recv", with = "duration_secs")]
    pub syn_recv: Duration, // Domyślnie 60s

    #[serde(default = "tcp_t_established", with = "duration_secs")]
    pub established: Duration, // Domyślnie 432000s

    #[serde(default = "tcp_t_fin_wait", with = "duration_secs")]
    pub fin_wait: Duration, // Domyślnie 120s

    #[serde(default = "tcp_t_close_wait", with = "duration_secs")]
    pub close_wait: Duration, // Domyślnie 60s

    #[serde(default = "tcp_t_last_ack", with = "duration_secs")]
    pub last_ack: Duration, // Domyślnie 30s

    #[serde(default = "tcp_t_time_wait", with = "duration_secs")]
    pub time_wait: Duration, // Domyślnie 120s

    #[serde(default = "tcp_t_close", with = "duration_secs")]
    pub close: Duration, // Domyślnie 10s

    #[serde(default = "tcp_t_max_retrans", with = "duration_secs")]
    pub max_retrans: Duration, // Domyślnie 300s

    #[serde(default = "tcp_t_unacknowledged", with = "duration_secs")]
    pub unacknowledged: Duration, // Domyślnie 300s
}

impl Default for TcpTimeouts {
    fn default() -> Self {
        Self {
            syn_sent: tcp_t_syn_sent(),
            syn_recv: tcp_t_syn_recv(),
            established: tcp_t_established(),
            fin_wait: tcp_t_fin_wait(),
            close_wait: tcp_t_close_wait(),
            last_ack: tcp_t_last_ack(),
            time_wait: tcp_t_time_wait(),
            close: tcp_t_close(),
            max_retrans: tcp_t_max_retrans(),
            unacknowledged: tcp_t_unacknowledged(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UdpConfig {
    #[serde(default = "udp_t", with = "duration_secs")]
    pub timeout: Duration,

    #[serde(default = "udp_t_stream", with = "duration_secs")]
    pub stream_timeout: Duration,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self { timeout: udp_t(), stream_timeout: udp_t_stream() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IcmpConfig {
    #[serde(default = "icmp_t", with = "duration_secs")]
    pub timeout: Duration,
}

impl Default for IcmpConfig {
    fn default() -> Self {
        Self { timeout: icmp_t() }
    }
}

fn default_max_entries() -> u32 { 262_144 }
fn default_htable_size() -> u32 { 65_536 }
fn default_gc_interval() -> Duration { Duration::from_secs(5) }
fn default_log_invalid() -> LogInvalid { LogInvalid::None }
fn default_events_enabled() -> bool { true }
fn default_generic_timeout() -> Duration { Duration::from_secs(600) }
fn default_max_retrans() -> u8 { 3 }
fn default_true() -> bool { true }

fn tcp_t_syn_sent()       -> Duration { Duration::from_secs(120) }
fn tcp_t_syn_recv()       -> Duration { Duration::from_secs(60) }
fn tcp_t_established()    -> Duration { Duration::from_secs(432_000) }
fn tcp_t_fin_wait()       -> Duration { Duration::from_secs(120) }
fn tcp_t_close_wait()     -> Duration { Duration::from_secs(60) }
fn tcp_t_last_ack()       -> Duration { Duration::from_secs(30) }
fn tcp_t_time_wait()      -> Duration { Duration::from_secs(120) }
fn tcp_t_close()          -> Duration { Duration::from_secs(10) }
fn tcp_t_max_retrans()    -> Duration { Duration::from_secs(300) }
fn tcp_t_unacknowledged() -> Duration { Duration::from_secs(300) }

fn udp_t()        -> Duration { Duration::from_secs(30) }
fn udp_t_stream() -> Duration { Duration::from_secs(120) }
fn icmp_t()       -> Duration { Duration::from_secs(30) }

mod duration_secs {
    use std::time::Duration;
    use serde::{ Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;

        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_passes_validation() {
        ConntrackConfig::default().validate().unwrap();
    }

    #[test]
    fn rejects_tiny_max_entries() {
        let mut c = ConntrackConfig::default();
        c.max_entries = 100;

        assert!(matches!(c.validate(), Err(ConfigError::TooSmall { .. })));
    }

    #[test]
    fn rejects_htable_larger_than_max() {
        let mut c = ConntrackConfig::default();
        c.htable_size = c.max_entries + 1;

        assert!(matches!(c.validate(), Err(ConfigError::Inconsistent(_))));
    }

    #[test]
    fn rejects_tiny_gc_interval() {
        let mut c = ConntrackConfig::default();
        c.gc_interval = Duration::from_millis(100);

        assert!(matches!(c.validate(), Err(ConfigError::TooSmall { .. })));
    }

    #[test]
    fn timeout_for_dispatches_per_proto() {
        let c = ConntrackConfig::default();

        assert_eq!(c.timeout_for(Protocol::Tcp), Duration::from_secs(432_000));
        assert_eq!(c.timeout_for(Protocol::Udp), Duration::from_secs(30));
        assert_eq!(c.timeout_for(Protocol::Icmp), Duration::from_secs(30));
    }

    #[test]
    fn deserialize_minimal_json() {
        let json = r#"{}"#;
        let c: ConntrackConfig = serde_json::from_str(json).unwrap();

        assert_eq!(c, ConntrackConfig::default());
    }

    #[test]
    fn deserialize_partial_overrides() {
        let json = r#"{"max_entries": 500000, "tcp": {"loose": false}}"#;
        let c: ConntrackConfig = serde_json::from_str(json).unwrap();

        assert_eq!(c.max_entries, 500_000);
        assert!(!c.tcp.loose);
        assert_eq!(c.tcp.timeout.established, Duration::from_secs(432_000));
    }

    #[test]
    fn duration_serializes_as_seconds() {
        let c = ConntrackConfig::default();
        let json = serde_json::to_string(&c).unwrap();

        assert!(json.contains("\"established\":432000"));
        assert!(json.contains("\"gc_interval\":5"));
    }
}