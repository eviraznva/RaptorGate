use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;

#[derive(Debug, Clone)]
pub enum DecryptionFailureReason {
    TlsAlert { alert_description: String },
    TcpReset,
    ConnectionClosedNoData,
    SuspectedPinnedCertificate,
    ClientCertificateRequired,
    UnsupportedTlsMode,
}

pub type PinningReason = DecryptionFailureReason;

impl std::fmt::Display for DecryptionFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TlsAlert { alert_description } => write!(f, "tls_alert:{alert_description}"),
            Self::TcpReset => write!(f, "tcp_reset"),
            Self::ConnectionClosedNoData => write!(f, "connection_closed_no_data"),
            Self::SuspectedPinnedCertificate => write!(f, "suspected_pinned_certificate"),
            Self::ClientCertificateRequired => write!(f, "client_certificate_required"),
            Self::UnsupportedTlsMode => write!(f, "unsupported_tls_mode"),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct DecryptionExclusionKey {
    domain: String,
    server_ip: Option<IpAddr>,
    server_port: u16,
}

impl DecryptionExclusionKey {
    fn new(domain: &str, server_ip: Option<IpAddr>, server_port: u16) -> Self {
        Self {
            domain: domain.to_lowercase(),
            server_ip,
            server_port,
        }
    }
}

struct FailureWindow {
    timestamps: VecDeque<Instant>,
    last_source_ip: IpAddr,
}

struct LocalExclusionEntry {
    activated_at: Instant,
    reason: DecryptionFailureReason,
    failure_count: u32,
    last_source_ip: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionFailureAction {
    CacheAndBypass,
    Block,
}

#[derive(Debug, Clone)]
pub struct PinningConfig {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub failure_window: Duration,
    pub bypass_ttl: Duration,
    pub action: DecryptionFailureAction,
    pub max_entries: usize,
}

impl Default for PinningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            bypass_ttl: Duration::from_secs(86400),
            action: DecryptionFailureAction::Block,
            max_entries: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionFailureReport {
    pub activated_exclusion: bool,
    pub action: DecryptionFailureAction,
    pub failure_count: u32,
}

pub struct PinningStats {
    pub active_bypasses: usize,
    pub tracked_failures: usize,
}

#[derive(Debug, Clone)]
pub struct DecryptionExclusionDetail {
    pub domain: String,
    pub server_ip: Option<IpAddr>,
    pub server_port: u16,
    pub reason: DecryptionFailureReason,
    pub failure_count: u32,
    pub last_source_ip: IpAddr,
}

pub struct PinningDetector {
    failures: DashMap<DecryptionExclusionKey, FailureWindow>,
    bypassed: DashMap<DecryptionExclusionKey, LocalExclusionEntry>,
    config: ArcSwap<PinningConfig>,
}

impl PinningDetector {
    pub fn new(config: PinningConfig) -> Self {
        Self {
            failures: DashMap::new(),
            bypassed: DashMap::new(),
            config: ArcSwap::new(config.into()),
        }
    }

    pub fn record_decryption_failure(
        &self,
        source_ip: IpAddr,
        _server_ip: Option<IpAddr>,
        server_port: u16,
        domain: &str,
        reason: DecryptionFailureReason,
    ) -> DecryptionFailureReport {
        let config = self.config.load();
        if !config.enabled {
            return DecryptionFailureReport {
                activated_exclusion: false,
                action: config.action,
                failure_count: 0,
            };
        }

        let key = DecryptionExclusionKey::new(domain, None, server_port);
        let now = Instant::now();
        let cutoff = now - config.failure_window;

        let mut entry = self
            .failures
            .entry(key.clone())
            .or_insert_with(|| FailureWindow {
                timestamps: VecDeque::new(),
                last_source_ip: source_ip,
            });

        entry.timestamps.retain(|t| *t >= cutoff);
        entry.timestamps.push_back(now);
        entry.last_source_ip = source_ip;

        let count = entry.timestamps.len() as u32;
        drop(entry);

        if count >= config.failure_threshold && config.action == DecryptionFailureAction::CacheAndBypass {
            self.failures.remove(&key);
            if self.bypassed.len() >= config.max_entries
                && let Some(oldest) = self.bypassed.iter().min_by_key(|entry| entry.activated_at).map(|entry| entry.key().clone()) {
                self.bypassed.remove(&oldest);
            }
            self.bypassed.insert(
                key,
                LocalExclusionEntry {
                    activated_at: now,
                    reason,
                    failure_count: count,
                    last_source_ip: source_ip,
                },
            );
            return DecryptionFailureReport {
                activated_exclusion: true,
                action: config.action,
                failure_count: count,
            };
        }

        DecryptionFailureReport {
            activated_exclusion: false,
            action: config.action,
            failure_count: count,
        }
    }

    pub fn is_target_decryption_excluded(
        &self,
        server_ip: Option<IpAddr>,
        server_port: u16,
        domain: &str,
    ) -> bool {
        let config = self.config.load();
        if !config.enabled {
            return false;
        }

        self.active_entry(domain, server_ip, server_port, config.bypass_ttl)
            .is_some()
    }

    pub fn reload_config(&self, config: PinningConfig) {
        self.config.store(Arc::new(config));
    }

    fn active_entry(
        &self,
        domain: &str,
        server_ip: Option<IpAddr>,
        server_port: u16,
        ttl: Duration,
    ) -> Option<(DecryptionExclusionKey, DecryptionExclusionDetail)> {
        let domain = domain.to_lowercase();
        let key = DecryptionExclusionKey::new(&domain, server_ip, server_port);
        if let Some(entry) = self.bypassed.get(&key) {
            if entry.activated_at.elapsed() < ttl {
                return Some((key, DecryptionExclusionDetail {
                    domain,
                    server_ip,
                    server_port,
                    reason: entry.reason.clone(),
                    failure_count: entry.failure_count,
                    last_source_ip: entry.last_source_ip,
                }));
            }
        }

        self.bypassed
            .iter()
            .find_map(|entry| {
                let entry_key = entry.key();
                let matches_domain = entry_key.domain == domain;
                let matches_port = entry_key.server_port == server_port;
                let matches_ip = server_ip.is_none() || entry_key.server_ip.is_none();
                if matches_domain && matches_port && matches_ip && entry.activated_at.elapsed() < ttl {
                    Some((entry_key.clone(), DecryptionExclusionDetail {
                        domain: entry_key.domain.clone(),
                        server_ip: entry_key.server_ip,
                        server_port: entry_key.server_port,
                        reason: entry.reason.clone(),
                        failure_count: entry.failure_count,
                        last_source_ip: entry.last_source_ip,
                    }))
                } else {
                    None
                }
            })
    }

    pub fn decryption_exclusion_detail(
        &self,
        domain: &str,
        server_ip: Option<IpAddr>,
        server_port: u16,
    ) -> Option<DecryptionExclusionDetail> {
        let config = self.config.load();
        if !config.enabled {
            return None;
        }

        self.active_entry(domain, server_ip, server_port, config.bypass_ttl)
            .map(|(_, detail)| detail)
    }

    pub fn list_decryption_exclusions(&self) -> Vec<DecryptionExclusionDetail> {
        let config = self.config.load();
        if !config.enabled {
            return Vec::new();
        }

        self.bypassed
            .iter()
            .filter_map(|entry| {
                if entry.activated_at.elapsed() >= config.bypass_ttl {
                    return None;
                }
                let key = entry.key();
                Some(DecryptionExclusionDetail {
                    domain: key.domain.clone(),
                    server_ip: key.server_ip,
                    server_port: key.server_port,
                    reason: entry.reason.clone(),
                    failure_count: entry.failure_count,
                    last_source_ip: entry.last_source_ip,
                })
            })
            .collect()
    }

    pub fn clear_decryption_exclusions(&self) -> usize {
        let removed = self.bypassed.len();
        self.bypassed.clear();
        removed
    }

    pub fn cleanup_expired(&self) -> usize {
        let config = self.config.load();
        let mut removed = 0;

        self.bypassed.retain(|_, entry| {
            let alive = entry.activated_at.elapsed() < config.bypass_ttl;
            if !alive {
                removed += 1;
            }
            alive
        });

        self.failures.retain(|_, window| {
            let cutoff = Instant::now() - config.failure_window;
            window.timestamps.retain(|t| *t >= cutoff);
            !window.timestamps.is_empty()
        });

        removed
    }

    pub fn failure_count_for(&self, source_ip: IpAddr, domain: &str) -> u32 {
        let config = self.config.load();
        let cutoff = Instant::now() - config.failure_window;
        self.failures
            .iter()
            .filter(|entry| entry.key().domain == domain.to_lowercase() && entry.last_source_ip == source_ip)
            .map(|entry| entry.timestamps.iter().filter(|t| **t >= cutoff).count() as u32)
            .sum()
    }

    pub fn stats(&self) -> PinningStats {
        self.cleanup_expired();
        PinningStats {
            active_bypasses: self.bypassed.len(),
            tracked_failures: self.failures.len(),
        }
    }

    pub fn bypass_detail(&self, source_ip: IpAddr, domain: &str) -> Option<(PinningReason, u32)> {
        self.decryption_exclusion_detail(domain, None, 443)
            .filter(|detail| detail.last_source_ip == source_ip || detail.server_ip.is_some())
            .map(|detail| (detail.reason, detail.failure_count))
            .or_else(|| {
                self.list_decryption_exclusions()
                    .into_iter()
                    .find(|detail| detail.domain == domain.to_lowercase()
                        && (detail.last_source_ip == source_ip || detail.server_ip.is_some()))
                    .map(|detail| (detail.reason, detail.failure_count))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn cfg(threshold: u32, window_secs: u64, ttl_secs: u64) -> PinningConfig {
        PinningConfig {
            enabled: true,
            failure_threshold: threshold,
            failure_window: Duration::from_secs(window_secs),
            bypass_ttl: Duration::from_secs(ttl_secs),
            action: DecryptionFailureAction::CacheAndBypass,
            ..PinningConfig::default()
        }
    }

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    fn other_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }

    fn reason() -> PinningReason {
        PinningReason::TcpReset
    }

    fn server_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
    }

    fn record_failure(det: &PinningDetector, source_ip: IpAddr, domain: &str, reason: PinningReason) -> bool {
        det.record_decryption_failure(source_ip, None, 443, domain, reason)
            .activated_exclusion
    }

    fn is_bypassed(det: &PinningDetector, domain: &str) -> bool {
        det.is_target_decryption_excluded(None, 443, domain)
    }

    #[test]
    fn default_action_blocks_decryption_failures() {
        assert_eq!(PinningConfig::default().action, DecryptionFailureAction::Block);
    }

    #[test]
    fn local_decryption_exclusion_cache_is_not_source_ip_scoped() {
        let det = PinningDetector::new(cfg(1, 60, 3600));

        let report = det.record_decryption_failure(
            localhost(),
            Some(server_ip()),
            443,
            "Pinned.Example",
            PinningReason::TcpReset,
        );

        assert!(report.activated_exclusion);
        assert!(det.is_target_decryption_excluded(Some(server_ip()), 443, "pinned.example"));
        assert!(det.is_target_decryption_excluded(Some(server_ip()), 443, "PINNED.EXAMPLE"));
    }

    #[test]
    fn local_decryption_exclusion_cache_is_not_server_ip_scoped_for_same_domain() {
        let det = PinningDetector::new(cfg(1, 60, 3600));
        let first_server_ip = IpAddr::V4(Ipv4Addr::new(142, 251, 155, 119));
        let second_server_ip = IpAddr::V4(Ipv4Addr::new(142, 251, 153, 119));

        let report = det.record_decryption_failure(
            localhost(),
            Some(first_server_ip),
            443,
            "www.google.com",
            PinningReason::TcpReset,
        );

        assert!(report.activated_exclusion);
        assert!(det.is_target_decryption_excluded(Some(second_server_ip), 443, "www.google.com"));
        assert_eq!(det.list_decryption_exclusions().len(), 1);
    }

    #[test]
    fn failure_threshold_counts_same_domain_across_server_ips() {
        let det = PinningDetector::new(cfg(2, 60, 3600));
        let first_server_ip = IpAddr::V4(Ipv4Addr::new(142, 251, 155, 119));
        let second_server_ip = IpAddr::V4(Ipv4Addr::new(142, 251, 153, 119));

        let first = det.record_decryption_failure(
            localhost(),
            Some(first_server_ip),
            443,
            "www.google.com",
            PinningReason::TcpReset,
        );
        let second = det.record_decryption_failure(
            localhost(),
            Some(second_server_ip),
            443,
            "www.google.com",
            PinningReason::TcpReset,
        );

        assert!(!first.activated_exclusion);
        assert!(second.activated_exclusion);
        assert!(det.is_target_decryption_excluded(Some(second_server_ip), 443, "www.google.com"));
    }

    #[test]
    fn block_action_does_not_activate_local_decryption_exclusion() {
        let mut config = cfg(1, 60, 3600);
        config.action = DecryptionFailureAction::Block;
        let det = PinningDetector::new(config);

        let report = det.record_decryption_failure(
            localhost(),
            Some(server_ip()),
            443,
            "pinned.example",
            PinningReason::TcpReset,
        );

        assert_eq!(report.action, DecryptionFailureAction::Block);
        assert!(!report.activated_exclusion);
        assert!(!det.is_target_decryption_excluded(Some(server_ip()), 443, "pinned.example"));
    }

    #[test]
    fn below_threshold_no_bypass() {
        let det = PinningDetector::new(cfg(3, 60, 3600));
        assert!(!record_failure(&det, localhost(), "example.com", reason()));
        assert!(!record_failure(&det, localhost(), "example.com", reason()));
        assert!(!is_bypassed(&det, "example.com"));
    }

    #[test]
    fn threshold_reached_activates_bypass() {
        let det = PinningDetector::new(cfg(3, 60, 3600));
        record_failure(&det, localhost(), "example.com", reason());
        record_failure(&det, localhost(), "example.com", reason());
        assert!(record_failure(&det, localhost(), "example.com", reason()));
        assert!(is_bypassed(&det, "example.com"));
    }

    #[test]
    fn different_source_ip_shares_local_exclusion() {
        let det = PinningDetector::new(cfg(2, 60, 3600));
        record_failure(&det, localhost(), "example.com", reason());
        record_failure(&det, other_ip(), "example.com", reason());
        assert!(is_bypassed(&det, "example.com"));
    }

    #[test]
    fn different_domains_independent() {
        let det = PinningDetector::new(cfg(2, 60, 3600));
        record_failure(&det, localhost(), "a.com", reason());
        record_failure(&det, localhost(), "b.com", reason());
        assert!(!is_bypassed(&det, "a.com"));
        assert!(!is_bypassed(&det, "b.com"));
    }

    #[test]
    fn case_insensitive_domain() {
        let det = PinningDetector::new(cfg(2, 60, 3600));
        record_failure(&det, localhost(), "Example.COM", reason());
        assert!(record_failure(&det, localhost(), "example.com", reason()));
        assert!(is_bypassed(&det, "EXAMPLE.com"));
    }

    #[test]
    fn bypass_expires_after_ttl() {
        let det = PinningDetector::new(cfg(1, 60, 0));
        assert!(record_failure(&det, localhost(), "example.com", reason()));
        assert!(!is_bypassed(&det, "example.com"));
    }

    #[test]
    fn cleanup_removes_expired() {
        let det = PinningDetector::new(cfg(1, 60, 0));
        record_failure(&det, localhost(), "a.com", reason());
        record_failure(&det, localhost(), "b.com", reason());
        let removed = det.cleanup_expired();
        assert_eq!(removed, 2);
        assert_eq!(det.stats().active_bypasses, 0);
    }

    #[test]
    fn disabled_config_skips_detection() {
        let mut c = cfg(1, 60, 3600);
        c.enabled = false;
        let det = PinningDetector::new(c);
        assert!(!record_failure(&det, localhost(), "example.com", reason()));
        assert!(!is_bypassed(&det, "example.com"));
    }

    #[test]
    fn stats_reflect_state() {
        let det = PinningDetector::new(cfg(3, 60, 3600));
        record_failure(&det, localhost(), "a.com", reason());
        record_failure(&det, other_ip(), "b.com", reason());
        let s = det.stats();
        assert_eq!(s.tracked_failures, 2);
        assert_eq!(s.active_bypasses, 0);
    }

    #[test]
    fn bypass_detail_returns_info() {
        let det = PinningDetector::new(cfg(1, 60, 3600));
        record_failure(
            &det,
            localhost(),
            "pin.com",
            PinningReason::TlsAlert {
                alert_description: "bad_certificate".into(),
            },
        );
        let (reason, count) = det.bypass_detail(localhost(), "pin.com").unwrap();
        assert_eq!(count, 1);
        assert!(matches!(reason, PinningReason::TlsAlert { .. }));
    }

    #[test]
    fn activation_clears_failure_window() {
        let det = PinningDetector::new(cfg(2, 60, 3600));
        record_failure(&det, localhost(), "x.com", reason());
        record_failure(&det, localhost(), "x.com", reason());
        assert!(is_bypassed(&det, "x.com"));
        assert_eq!(det.stats().tracked_failures, 0);
    }

    #[test]
    fn reason_display() {
        assert_eq!(PinningReason::TcpReset.to_string(), "tcp_reset");
        assert_eq!(
            PinningReason::TlsAlert {
                alert_description: "bad_certificate".into()
            }
            .to_string(),
            "tls_alert:bad_certificate"
        );
        assert_eq!(
            PinningReason::ConnectionClosedNoData.to_string(),
            "connection_closed_no_data"
        );
    }
}
