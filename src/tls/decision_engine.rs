use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::dpi::TlsAction;
use crate::tls::domain_trie::DomainTrie;
use crate::tls::server_key_store::ServerKeyStore;

// Jedno źródło prawdy dla decyzji inspekcji TLS (pipeline + proxy).
pub struct TlsDecisionEngine {
    bypass_trie: ArcSwap<DomainTrie>,
    server_key_store: Arc<ServerKeyStore>,
}

impl TlsDecisionEngine {
    pub fn new(bypass_domains: &[String], server_key_store: Arc<ServerKeyStore>) -> Self {
        let trie = DomainTrie::from_domains(bypass_domains);
        Self {
            bypass_trie: ArcSwap::new(Arc::new(trie)),
            server_key_store,
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

        if ech_detected && sni.is_none() {
            return TlsAction::Block;
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
        TlsDecisionEngine::new(&ds, store)
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
}
