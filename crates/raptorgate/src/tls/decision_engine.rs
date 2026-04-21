use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio_util::sync::CancellationToken;

use crate::dpi::TlsAction;
use crate::tls::domain_trie::DomainTrie;
use crate::tls::pinning_detector::{PinningConfig, PinningDetector, PinningReason};
use crate::tls::server_key_store::ServerKeyStore;

// Wspolny detektor pinningu — ten sam Arc trafia do runtime'u TLS i query_server.

#[derive(Debug, Clone)]
pub struct EchTlsPolicy {
    pub block_ech_no_sni: bool,
    pub block_all_ech: bool,
}

impl Default for EchTlsPolicy {
    fn default() -> Self {
        Self {
            block_ech_no_sni: true,
            block_all_ech: false,
        }
    }
}

// Jedno źródło prawdy dla decyzji inspekcji TLS w runtime proxy.
pub struct TlsDecisionEngine {
    bypass_trie: ArcSwap<DomainTrie>,
    known_pinned_trie: ArcSwap<DomainTrie>,
    server_key_store: Arc<ServerKeyStore>,
    ech_policy: ArcSwap<EchTlsPolicy>,
    pinning_detector: Arc<PinningDetector>,
}

impl TlsDecisionEngine {
    pub fn new(
        bypass_domains: &[String],
        server_key_store: Arc<ServerKeyStore>,
        ech_policy: EchTlsPolicy,
        pinning_config: PinningConfig,
    ) -> Self {
        let trie = DomainTrie::from_domains(bypass_domains);
        Self {
            bypass_trie: ArcSwap::new(Arc::new(trie)),
            known_pinned_trie: ArcSwap::new(Arc::new(DomainTrie::new())),
            server_key_store,
            ech_policy: ArcSwap::new(Arc::new(ech_policy)),
            pinning_detector: Arc::new(PinningDetector::new(pinning_config)),
        }
    }

    pub fn pinning_detector_arc(&self) -> Arc<PinningDetector> {
        Arc::clone(&self.pinning_detector)
    }

    // Decyzja inspekcji: inbound (klucz serwera) vs outbound (MITM) vs bypass/block.
    pub fn decide(
        &self,
        sni: Option<&str>,
        ech_detected: bool,
        dst_ip: Option<IpAddr>,
        dst_port: u16,
        source_ip: Option<IpAddr>,
    ) -> TlsAction {
        if let Some(ip) = dst_ip {
            let addr = SocketAddr::new(ip, dst_port);
            if let Some(entry) = self.server_key_store.get_entry(addr) {
                if !entry.enabled || entry.bypass {
                    return TlsAction::Bypass;
                }
                return TlsAction::Intercept;
            }
        }

        let trie = self.bypass_trie.load();
        if let Some(domain) = sni {
            if trie.contains(domain) {
                return TlsAction::Bypass;
            }
            if self.known_pinned_trie.load().contains(domain) {
                return TlsAction::Bypass;
            }
        }

        if let (Some(src), Some(domain)) = (source_ip, sni) {
            if self.pinning_detector.is_bypassed(src, domain) {
                return TlsAction::Bypass;
            }
        }

        if ech_detected {
            let policy = self.ech_policy.load();
            if policy.block_all_ech {
                return TlsAction::Block;
            }
            match sni {
                Some(outer_sni) => {
                    if trie.contains(outer_sni) {
                        return TlsAction::Bypass;
                    }
                    return TlsAction::Intercept;
                }
                None => {
                    if policy.block_ech_no_sni {
                        return TlsAction::Block;
                    }
                    return TlsAction::Intercept;
                }
            }
        }

        TlsAction::Intercept
    }

    // Atomowa podmiana listy bypass (hot-reload z backendu).
    pub fn reload_bypass(&self, domains: &[String]) {
        let trie = DomainTrie::from_domains(domains);
        self.bypass_trie.store(Arc::new(trie));
        tracing::info!(count = domains.len(), "TLS bypass list reloaded");
    }

    /// Atomowa podmiana polityki ECH (hot-reload z backendu).
    pub fn reload_ech_policy(&self, policy: EchTlsPolicy) {
        self.ech_policy.store(Arc::new(policy));
        tracing::info!("ECH TLS policy reloaded");
    }

    pub fn reload_known_pinned_domains(&self, domains: &[String]) {
        let trie = DomainTrie::from_domains(domains);
        self.known_pinned_trie.store(Arc::new(trie));
        tracing::info!(count = domains.len(), "TLS known pinned domains reloaded");
    }

    pub fn report_pinning_failure(
        &self,
        source_ip: IpAddr,
        domain: &str,
        reason: PinningReason,
    ) -> bool {
        self.pinning_detector
            .record_failure(source_ip, domain, reason)
    }

    pub fn pinning_detector(&self) -> &PinningDetector {
        &self.pinning_detector
    }

    pub fn server_key_store(&self) -> &Arc<ServerKeyStore> {
        &self.server_key_store
    }

    pub fn spawn_maintenance_task(self: &Arc<Self>, cancel: CancellationToken) {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(300));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tick.tick() => {
                        let removed = engine.pinning_detector.cleanup_expired();
                        if removed > 0 {
                            tracing::debug!(removed, "Expired pinning bypass entries removed");
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn engine(domains: &[&str]) -> TlsDecisionEngine {
        let ds: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
        let store = Arc::new(ServerKeyStore::new("/tmp/test-pki-decision"));
        TlsDecisionEngine::new(
            &ds,
            store,
            EchTlsPolicy::default(),
            PinningConfig::default(),
        )
    }

    fn engine_with_ech_policy(domains: &[&str], policy: EchTlsPolicy) -> TlsDecisionEngine {
        let ds: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
        let store = Arc::new(ServerKeyStore::new("/tmp/test-pki-decision"));
        TlsDecisionEngine::new(&ds, store, policy, PinningConfig::default())
    }

    fn temp_dir() -> String {
        let dir = std::env::temp_dir()
            .join(uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().to_string()
    }

    fn make_server_cert() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, "test-server.local");
        params.subject_alt_names = vec![SanType::DnsName(
            "test-server.local".to_string().try_into().unwrap(),
        )];
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn bypass_by_sni() {
        let e = engine(&["bank.com"]);
        assert_eq!(
            e.decide(Some("www.bank.com"), false, None, 443, None),
            TlsAction::Bypass
        );
    }

    #[test]
    fn intercept_unknown_domain() {
        let e = engine(&["bank.com"]);
        assert_eq!(
            e.decide(Some("example.com"), false, None, 443, None),
            TlsAction::Intercept
        );
    }

    #[test]
    fn block_ech_no_sni() {
        let e = engine(&[]);
        assert_eq!(e.decide(None, true, None, 443, None), TlsAction::Block);
    }

    #[test]
    fn intercept_default() {
        let e = engine(&[]);
        assert_eq!(
            e.decide(Some("example.com"), false, None, 443, None),
            TlsAction::Intercept
        );
    }

    #[test]
    fn reload_bypass() {
        let e = engine(&[]);
        assert_eq!(
            e.decide(Some("bank.com"), false, None, 443, None),
            TlsAction::Intercept
        );
        e.reload_bypass(&["bank.com".into()]);
        assert_eq!(
            e.decide(Some("bank.com"), false, None, 443, None),
            TlsAction::Bypass
        );
    }

    #[test]
    fn ech_with_outer_sni_intercept() {
        let e = engine(&["bank.com"]);
        assert_eq!(
            e.decide(Some("cloudflare-ech.com"), true, None, 443, None),
            TlsAction::Intercept
        );
    }

    #[test]
    fn ech_with_outer_sni_bypass() {
        let e = engine(&["cloudflare-ech.com"]);
        assert_eq!(
            e.decide(Some("cloudflare-ech.com"), true, None, 443, None),
            TlsAction::Bypass
        );
    }

    #[test]
    fn ech_block_all_policy() {
        let e = engine_with_ech_policy(
            &[],
            EchTlsPolicy {
                block_all_ech: true,
                block_ech_no_sni: true,
            },
        );
        assert_eq!(
            e.decide(Some("example.com"), true, None, 443, None),
            TlsAction::Block
        );
    }

    #[test]
    fn ech_no_sni_allowed_when_policy_off() {
        let e = engine_with_ech_policy(
            &[],
            EchTlsPolicy {
                block_ech_no_sni: false,
                block_all_ech: false,
            },
        );
        assert_eq!(e.decide(None, true, None, 443, None), TlsAction::Intercept);
    }

    #[test]
    fn ech_policy_reload() {
        let e = engine(&[]);
        assert_eq!(e.decide(None, true, None, 443, None), TlsAction::Block);
        e.reload_ech_policy(EchTlsPolicy {
            block_ech_no_sni: false,
            block_all_ech: false,
        });
        assert_eq!(e.decide(None, true, None, 443, None), TlsAction::Intercept);
    }

    #[test]
    fn known_pinned_domains_bypass() {
        let e = engine(&[]);
        e.reload_known_pinned_domains(&["*.apple.com".into()]);
        assert_eq!(
            e.decide(Some("api.apple.com"), false, None, 443, None),
            TlsAction::Bypass
        );
    }

    #[test]
    fn pinning_auto_bypass_after_threshold() {
        let cfg = PinningConfig {
            enabled: true,
            failure_threshold: 2,
            ..PinningConfig::default()
        };
        let ds: Vec<String> = Vec::new();
        let store = Arc::new(ServerKeyStore::new("/tmp/test-pki-pin"));
        let e = TlsDecisionEngine::new(&ds, store, EchTlsPolicy::default(), cfg);

        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            e.decide(Some("pinned.app"), false, None, 443, Some(src)),
            TlsAction::Intercept
        );

        e.report_pinning_failure(src, "pinned.app", PinningReason::TcpReset);
        e.report_pinning_failure(src, "pinned.app", PinningReason::TcpReset);

        assert_eq!(
            e.decide(Some("pinned.app"), false, None, 443, Some(src)),
            TlsAction::Bypass
        );
        assert_eq!(
            e.decide(Some("pinned.app"), false, None, 443, None),
            TlsAction::Intercept
        );
    }

    #[test]
    fn configured_inbound_service_intercepts() {
        let dir = temp_dir();
        let store = Arc::new(ServerKeyStore::new(&dir));
        let (cert, key) = make_server_cert();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 20, 10)), 443);

        store
            .add(
                addr,
                &cert,
                &key,
                "decision-ref-enabled",
                "test-server.local",
                "FP",
                false,
                true,
            )
            .unwrap();

        let e = TlsDecisionEngine::new(&[], store, EchTlsPolicy::default(), PinningConfig::default());
        assert_eq!(
            e.decide(Some("h2-firewall.lab"), false, Some(addr.ip()), addr.port(), None),
            TlsAction::Intercept
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn disabled_inbound_service_bypasses() {
        let dir = temp_dir();
        let store = Arc::new(ServerKeyStore::new(&dir));
        let (cert, key) = make_server_cert();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 20, 10)), 443);

        store
            .add(
                addr,
                &cert,
                &key,
                "decision-ref-disabled",
                "test-server.local",
                "FP",
                false,
                false,
            )
            .unwrap();

        let e = TlsDecisionEngine::new(&[], store, EchTlsPolicy::default(), PinningConfig::default());
        assert_eq!(
            e.decide(Some("h2-firewall.lab"), false, Some(addr.ip()), addr.port(), None),
            TlsAction::Bypass
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
