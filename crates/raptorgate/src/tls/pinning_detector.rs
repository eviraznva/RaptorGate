use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;

#[derive(Debug, Clone)]
pub enum PinningReason {
    TlsAlert { alert_description: String },
    TcpReset,
    ConnectionClosedNoData,
}

impl std::fmt::Display for PinningReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TlsAlert { alert_description } => write!(f, "tls_alert:{alert_description}"),
            Self::TcpReset => write!(f, "tcp_reset"),
            Self::ConnectionClosedNoData => write!(f, "connection_closed_no_data"),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct PinningKey {
    source_ip: IpAddr,
    domain: String,
}

impl PinningKey {
    fn new(source_ip: IpAddr, domain: &str) -> Self {
        Self {
            source_ip,
            domain: domain.to_lowercase(),
        }
    }
}

struct FailureWindow {
    timestamps: VecDeque<Instant>,
}

struct BypassEntry {
    activated_at: Instant,
    reason: PinningReason,
    failure_count: u32,
}

#[derive(Debug, Clone)]
pub struct PinningConfig {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub failure_window: Duration,
    pub bypass_ttl: Duration,
}

impl Default for PinningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            bypass_ttl: Duration::from_secs(86400),
        }
    }
}

pub struct PinningStats {
    pub active_bypasses: usize,
    pub tracked_failures: usize,
}

/// Behawioralna detekcja certificate pinningu per (source_ip, sni).
pub struct PinningDetector {
    failures: DashMap<PinningKey, FailureWindow>,
    bypassed: DashMap<PinningKey, BypassEntry>,
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

    /// Rejestruje failure handshake. Zwraca true jeśli aktywowano auto-bypass.
    pub fn record_failure(&self, source_ip: IpAddr, domain: &str, reason: PinningReason) -> bool {
        let config = self.config.load();
        if !config.enabled {
            return false;
        }

        let key = PinningKey::new(source_ip, domain);
        let now = Instant::now();
        let cutoff = now - config.failure_window;

        let mut entry = self
            .failures
            .entry(key.clone())
            .or_insert_with(|| FailureWindow {
                timestamps: VecDeque::new(),
            });

        entry.timestamps.retain(|t| *t >= cutoff);
        entry.timestamps.push_back(now);

        let count = entry.timestamps.len() as u32;
        drop(entry);

        if count >= config.failure_threshold {
            self.failures.remove(&key);
            self.bypassed.insert(
                key,
                BypassEntry {
                    activated_at: now,
                    reason,
                    failure_count: count,
                },
            );
            return true;
        }

        false
    }

    pub fn is_bypassed(&self, source_ip: IpAddr, domain: &str) -> bool {
        let config = self.config.load();
        if !config.enabled {
            return false;
        }

        let key = PinningKey::new(source_ip, domain);
        match self.bypassed.get(&key) {
            Some(entry) => entry.activated_at.elapsed() < config.bypass_ttl,
            None => false,
        }
    }

    /// Usuwa wygasłe wpisy, zwraca liczbę usuniętych.
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

    pub fn reload_config(&self, config: PinningConfig) {
        self.config.store(config.into());
        tracing::info!("Pinning detection config reloaded");
    }

    /// Liczba aktywnych failure'ów dla (source_ip, domain) w bieżącym oknie.
    /// Read-only accessor używany przez ML feature vector — nie mutuje stanu.
    pub fn failure_count_for(&self, source_ip: IpAddr, domain: &str) -> u32 {
        let config = self.config.load();
        let key = PinningKey::new(source_ip, domain);
        let cutoff = Instant::now() - config.failure_window;
        self.failures
            .get(&key)
            .map(|entry| entry.timestamps.iter().filter(|t| **t >= cutoff).count() as u32)
            .unwrap_or(0)
    }

    pub fn stats(&self) -> PinningStats {
        PinningStats {
            active_bypasses: self.bypassed.len(),
            tracked_failures: self.failures.len(),
        }
    }

    pub fn bypass_detail(&self, source_ip: IpAddr, domain: &str) -> Option<(PinningReason, u32)> {
        let key = PinningKey::new(source_ip, domain);
        self.bypassed
            .get(&key)
            .map(|e| (e.reason.clone(), e.failure_count))
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

    #[test]
    fn below_threshold_no_bypass() {
        let det = PinningDetector::new(cfg(3, 60, 3600));
        assert!(!det.record_failure(localhost(), "example.com", reason()));
        assert!(!det.record_failure(localhost(), "example.com", reason()));
        assert!(!det.is_bypassed(localhost(), "example.com"));
    }

    #[test]
    fn threshold_reached_activates_bypass() {
        let det = PinningDetector::new(cfg(3, 60, 3600));
        det.record_failure(localhost(), "example.com", reason());
        det.record_failure(localhost(), "example.com", reason());
        assert!(det.record_failure(localhost(), "example.com", reason()));
        assert!(det.is_bypassed(localhost(), "example.com"));
    }

    #[test]
    fn different_source_ip_independent() {
        let det = PinningDetector::new(cfg(2, 60, 3600));
        det.record_failure(localhost(), "example.com", reason());
        det.record_failure(other_ip(), "example.com", reason());
        assert!(!det.is_bypassed(localhost(), "example.com"));
        assert!(!det.is_bypassed(other_ip(), "example.com"));
    }

    #[test]
    fn different_domains_independent() {
        let det = PinningDetector::new(cfg(2, 60, 3600));
        det.record_failure(localhost(), "a.com", reason());
        det.record_failure(localhost(), "b.com", reason());
        assert!(!det.is_bypassed(localhost(), "a.com"));
        assert!(!det.is_bypassed(localhost(), "b.com"));
    }

    #[test]
    fn case_insensitive_domain() {
        let det = PinningDetector::new(cfg(2, 60, 3600));
        det.record_failure(localhost(), "Example.COM", reason());
        assert!(det.record_failure(localhost(), "example.com", reason()));
        assert!(det.is_bypassed(localhost(), "EXAMPLE.com"));
    }

    #[test]
    fn bypass_expires_after_ttl() {
        let det = PinningDetector::new(cfg(1, 60, 0));
        assert!(det.record_failure(localhost(), "example.com", reason()));
        assert!(!det.is_bypassed(localhost(), "example.com"));
    }

    #[test]
    fn cleanup_removes_expired() {
        let det = PinningDetector::new(cfg(1, 60, 0));
        det.record_failure(localhost(), "a.com", reason());
        det.record_failure(localhost(), "b.com", reason());
        let removed = det.cleanup_expired();
        assert_eq!(removed, 2);
        assert_eq!(det.stats().active_bypasses, 0);
    }

    #[test]
    fn disabled_config_skips_detection() {
        let mut c = cfg(1, 60, 3600);
        c.enabled = false;
        let det = PinningDetector::new(c);
        assert!(!det.record_failure(localhost(), "example.com", reason()));
        assert!(!det.is_bypassed(localhost(), "example.com"));
    }

    #[test]
    fn stats_reflect_state() {
        let det = PinningDetector::new(cfg(3, 60, 3600));
        det.record_failure(localhost(), "a.com", reason());
        det.record_failure(other_ip(), "b.com", reason());
        let s = det.stats();
        assert_eq!(s.tracked_failures, 2);
        assert_eq!(s.active_bypasses, 0);
    }

    #[test]
    fn bypass_detail_returns_info() {
        let det = PinningDetector::new(cfg(1, 60, 3600));
        det.record_failure(
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
        det.record_failure(localhost(), "x.com", reason());
        det.record_failure(localhost(), "x.com", reason());
        assert!(det.is_bypassed(localhost(), "x.com"));
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
