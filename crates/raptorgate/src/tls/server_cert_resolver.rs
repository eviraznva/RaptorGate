use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use super::CertForger;

// Resolver fałszujący certyfikat per domena na podstawie SNI.
pub struct SniForgingResolver {
    forger: Arc<CertForger>,
}

impl SniForgingResolver {
    pub fn new(forger: Arc<CertForger>) -> Self {
        Self { forger }
    }
}

impl std::fmt::Debug for SniForgingResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniForgingResolver").finish()
    }
}

impl ResolvesServerCert for SniForgingResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let domain = client_hello.server_name()?;

        let forged = self.forger.forge(domain, &[]).ok()?;
        let certified = forged.to_certified_key().ok()?;

        Some(certified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

    fn make_ca() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn make_resolver() -> SniForgingResolver {
        let (cert_pem, key_pem) = make_ca();
        let forger = Arc::new(CertForger::new(&cert_pem, &key_pem, 100).unwrap());
        SniForgingResolver::new(forger)
    }

    #[test]
    fn resolver_creates_without_panic() {
        let _resolver = make_resolver();
    }

    #[test]
    fn resolver_is_debug() {
        let resolver = make_resolver();
        let debug = format!("{resolver:?}");
        assert!(debug.contains("SniForgingResolver"));
    }

    #[test]
    fn resolver_can_be_used_in_server_config() {
        let resolver = make_resolver();
        let config = super::super::rustls_config::build_server_config(Arc::new(resolver));
        assert!(config.is_ok());
    }
}
