use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::dpi::TlsAction;
use crate::tls::domain_trie::DomainTrie;
use crate::tls::server_key_store::ServerKeyStore;

/// Polityka ECH na poziomie TLS.
#[derive(Debug, Clone)]
pub struct EchTlsPolicy {
    pub block_ech_no_sni: bool,
    pub block_all_ech: bool,
}

impl Default for EchTlsPolicy {
    fn default() -> Self {
        Self { block_ech_no_sni: true, block_all_ech: false }
    }
}

// Jedno źródło prawdy dla decyzji inspekcji TLS (pipeline + proxy).
pub struct TlsDecisionEngine {
    bypass_trie: ArcSwap<DomainTrie>,
    server_key_store: Arc<ServerKeyStore>,
    ech_policy: ArcSwap<EchTlsPolicy>,
}

impl TlsDecisionEngine {
    pub fn new(bypass_domains: &[String], server_key_store: Arc<ServerKeyStore>, ech_policy: EchTlsPolicy) -> Self {
        let trie = DomainTrie::from_domains(bypass_domains);
        Self {
            bypass_trie: ArcSwap::new(Arc::new(trie)),
            server_key_store,
            ech_policy: ArcSwap::new(Arc::new(ech_policy)),
        }
    }

    // Decyzja inspekcji: inbound (klucz serwera) vs outbound (MITM) vs bypass/block.
    pub fn decide(
        &self,
        sni: Option<&str>,
        ech_detected: bool,
        dst_ip: Option<IpAddr>,
        dst_port: u16,
    ) -> TlsAction {
        if let Some(ip) = dst_ip {
            let addr = SocketAddr::new(ip, dst_port);
            if let Some(entry) = self.server_key_store.get_entry(addr) {
                if entry.bypass {
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

    // Sprawdza bypass tylko po domenie (dla proxy, bez inbound).
    pub fn is_domain_bypassed(&self, domain: &str) -> bool {
        self.bypass_trie.load().contains(domain)
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

    pub fn server_key_store(&self) -> &Arc<ServerKeyStore> {
        &self.server_key_store
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(domains: &[&str]) -> TlsDecisionEngine {
        let ds: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
        let store = Arc::new(ServerKeyStore::new("/tmp/test-pki-decision"));
        TlsDecisionEngine::new(&ds, store, EchTlsPolicy::default())
    }

    fn engine_with_ech_policy(domains: &[&str], policy: EchTlsPolicy) -> TlsDecisionEngine {
        let ds: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
        let store = Arc::new(ServerKeyStore::new("/tmp/test-pki-decision"));
        TlsDecisionEngine::new(&ds, store, policy)
    }

    #[test]
    fn bypass_by_sni() {
        let e = engine(&["bank.com"]);
        assert_eq!(e.decide(Some("www.bank.com"), false, None, 443), TlsAction::Bypass);
    }

    #[test]
    fn intercept_unknown_domain() {
        let e = engine(&["bank.com"]);
        assert_eq!(e.decide(Some("example.com"), false, None, 443), TlsAction::Intercept);
    }

    #[test]
    fn block_ech_no_sni() {
        let e = engine(&[]);
        assert_eq!(e.decide(None, true, None, 443), TlsAction::Block);
    }

    #[test]
    fn intercept_default() {
        let e = engine(&[]);
        assert_eq!(e.decide(Some("example.com"), false, None, 443), TlsAction::Intercept);
    }

    #[test]
    fn reload_bypass() {
        let e = engine(&[]);
        assert_eq!(e.decide(Some("bank.com"), false, None, 443), TlsAction::Intercept);
        e.reload_bypass(&["bank.com".into()]);
        assert_eq!(e.decide(Some("bank.com"), false, None, 443), TlsAction::Bypass);
    }

    #[test]
    fn is_domain_bypassed() {
        let e = engine(&["example.com"]);
        assert!(e.is_domain_bypassed("sub.example.com"));
        assert!(!e.is_domain_bypassed("other.com"));
    }

    #[test]
    fn ech_with_outer_sni_intercept() {
        let e = engine(&["bank.com"]);
        assert_eq!(e.decide(Some("cloudflare-ech.com"), true, None, 443), TlsAction::Intercept);
    }

    #[test]
    fn ech_with_outer_sni_bypass() {
        let e = engine(&["cloudflare-ech.com"]);
        assert_eq!(e.decide(Some("cloudflare-ech.com"), true, None, 443), TlsAction::Bypass);
    }

    #[test]
    fn ech_block_all_policy() {
        let e = engine_with_ech_policy(&[], EchTlsPolicy { block_all_ech: true, block_ech_no_sni: true });
        assert_eq!(e.decide(Some("example.com"), true, None, 443), TlsAction::Block);
    }

    #[test]
    fn ech_no_sni_allowed_when_policy_off() {
        let e = engine_with_ech_policy(&[], EchTlsPolicy { block_ech_no_sni: false, block_all_ech: false });
        assert_eq!(e.decide(None, true, None, 443), TlsAction::Intercept);
    }

    #[test]
    fn ech_policy_reload() {
        let e = engine(&[]);
        assert_eq!(e.decide(None, true, None, 443), TlsAction::Block);
        e.reload_ech_policy(EchTlsPolicy { block_ech_no_sni: false, block_all_ech: false });
        assert_eq!(e.decide(None, true, None, 443), TlsAction::Intercept);
    }
}
