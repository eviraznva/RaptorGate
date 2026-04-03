use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use lru::LruCache;
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use time::OffsetDateTime;

// Sfałszowany certyfikat domeny podpisany przez CA firewalla.
pub struct ForgedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
}

// Statystyki cache certyfikatów.
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub size: usize,
    pub capacity: usize,
}

// Generuje certyfikaty per-domena podpisane CA firewalla z cache LRU.
pub struct CertForger {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    cache: Mutex<LruCache<String, Arc<ForgedCert>>>,
    capacity: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl CertForger {
    pub fn new(
        ca_cert_pem: &str,
        ca_key_pem: &str,
        cache_capacity: usize,
    ) -> anyhow::Result<Self> {
        let capacity = cache_capacity.max(1);

        let ca_key =
            KeyPair::from_pem(ca_key_pem).context("Failed to load CA key from PEM")?;

        let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .context("Failed to load CA certificate from PEM")?;

        let ca_cert = ca_params
            .self_signed(&ca_key)
            .context("Failed to reconstruct CA certificate")?;

        Ok(Self {
            ca_cert,
            ca_key,
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("capacity > 0"),
            )),
            capacity,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        })
    }

    // Zwraca certyfikat z cache lub generuje nowy.
    pub fn forge(
        &self,
        domain: &str,
        extra_sans: &[String],
    ) -> anyhow::Result<Arc<ForgedCert>> {
        let key = cache_key(domain, extra_sans);

        {
            let mut cache = self.cache.lock().expect("cache lock poisoned");
            if let Some(entry) = cache.get(&key) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Arc::clone(entry));
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        let cert = Arc::new(self.generate(domain, extra_sans)?);

        let mut cache = self.cache.lock().expect("cache lock poisoned");
        cache.put(key, Arc::clone(&cert));

        Ok(cert)
    }

    pub fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.lock().expect("cache lock poisoned");
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            size: cache.len(),
            capacity: self.capacity,
        }
    }

    fn generate(&self, domain: &str, extra_sans: &[String]) -> anyhow::Result<ForgedCert> {
        let leaf_key = KeyPair::generate().context("Failed to generate leaf key pair")?;

        let now = OffsetDateTime::now_utc();
        let expiry = now + time::Duration::days(365);

        let mut params = CertificateParams::default();
        params.not_before = now;
        params.not_after = expiry;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params
            .distinguished_name
            .push(DnType::CommonName, domain);

        let mut sans: Vec<String> = Vec::with_capacity(1 + extra_sans.len());
        push_dns_san(&mut sans, domain);
        for san in extra_sans {
            push_dns_san(&mut sans, san);
        }

        params.subject_alt_names = sans
            .iter()
            .map(|s| {
                SanType::DnsName(
                    s.clone()
                        .try_into()
                        .expect("invalid DNS name should have been filtered"),
                )
            })
            .collect();

        let cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .context("Failed to sign leaf certificate")?;

        Ok(ForgedCert {
            cert_der: cert.der().to_vec(),
            cert_pem: cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        })
    }
}

fn push_dns_san(sans: &mut Vec<String>, name: &str) {
    let normalized = name.to_lowercase();
    if !sans.contains(&normalized) {
        sans.push(normalized);
    }
}

fn cache_key(domain: &str, extra_sans: &[String]) -> String {
    let mut names: Vec<String> = Vec::with_capacity(1 + extra_sans.len());
    names.push(domain.to_lowercase());
    for san in extra_sans {
        let n = san.to_lowercase();
        if !names.contains(&n) {
            names.push(n);
        }
    }
    names.sort();
    names.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn forger() -> CertForger {
        let (cert_pem, key_pem) = make_ca();
        CertForger::new(&cert_pem, &key_pem, 100).unwrap()
    }

    fn parse_pem_cert(pem: &str) -> x509_parser::certificate::X509Certificate<'static> {
        use x509_parser::pem::parse_x509_pem;
        let (_, pem) = parse_x509_pem(pem.as_bytes()).unwrap();
        let owned = pem.contents;
        // SAFETY: rozszerzamy lifetime — dane żyją w boxie na stercie.
        let static_bytes: &'static [u8] = Box::leak(owned.into_boxed_slice());
        let (_, cert) = x509_parser::parse_x509_certificate(static_bytes).unwrap();
        cert
    }

    #[test]
    fn forge_produces_valid_pem() {
        let f = forger();
        let cert = f.forge("example.com", &[]).unwrap();
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!cert.cert_der.is_empty());
    }

    #[test]
    fn forge_cert_has_correct_cn() {
        let f = forger();
        let forged = f.forge("example.com", &[]).unwrap();
        let cert = parse_pem_cert(&forged.cert_pem);
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(cn, "example.com");
    }

    #[test]
    fn forge_cert_has_correct_issuer() {
        let f = forger();
        let forged = f.forge("example.com", &[]).unwrap();
        let cert = parse_pem_cert(&forged.cert_pem);
        let issuer_cn = cert
            .issuer()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(issuer_cn, "Test CA");
    }

    #[test]
    fn forge_cert_contains_domain_san() {
        use x509_parser::extensions::GeneralName;
        let f = forger();
        let forged = f.forge("example.com", &[]).unwrap();
        let cert = parse_pem_cert(&forged.cert_pem);
        let san_ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .unwrap();
        let san = san_ext.parsed_extension();
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = san {
            let dns_names: Vec<&str> = san
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(s) => Some(*s),
                    _ => None,
                })
                .collect();
            assert!(dns_names.contains(&"example.com"));
        } else {
            panic!("SAN extension not found");
        }
    }

    #[test]
    fn forge_cert_contains_extra_sans() {
        use x509_parser::extensions::GeneralName;
        let f = forger();
        let extra = vec!["www.example.com".into(), "api.example.com".into()];
        let forged = f.forge("example.com", &extra).unwrap();
        let cert = parse_pem_cert(&forged.cert_pem);
        let san_ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .unwrap();
        let san = san_ext.parsed_extension();
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = san {
            let dns_names: Vec<&str> = san
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(s) => Some(*s),
                    _ => None,
                })
                .collect();
            assert!(dns_names.contains(&"example.com"));
            assert!(dns_names.contains(&"www.example.com"));
            assert!(dns_names.contains(&"api.example.com"));
            assert_eq!(dns_names.len(), 3);
        } else {
            panic!("SAN extension not found");
        }
    }

    #[test]
    fn forge_cert_is_not_ca() {
        let f = forger();
        let forged = f.forge("example.com", &[]).unwrap();
        let cert = parse_pem_cert(&forged.cert_pem);
        let bc = cert.basic_constraints();
        match bc {
            Ok(Some(bc)) => assert!(!bc.value.ca),
            Ok(None) => {} // brak rozszerzenia = nie-CA
            Err(e) => panic!("Blad parsowania basic constraints: {e}"),
        }
    }

    #[test]
    fn forge_cert_has_server_auth_eku() {
        let f = forger();
        let forged = f.forge("example.com", &[]).unwrap();
        let cert = parse_pem_cert(&forged.cert_pem);
        let eku_ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE)
            .expect("EKU extension missing");
        let eku = eku_ext.parsed_extension();
        if let x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) = eku {
            assert!(eku.server_auth);
        } else {
            panic!("EKU extension parse failed");
        }
    }

    #[test]
    fn forge_cert_valid_roughly_one_year() {
        let f = forger();
        let forged = f.forge("example.com", &[]).unwrap();
        let cert = parse_pem_cert(&forged.cert_pem);
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        let days = (not_after - not_before) / 86400;
        assert!((364..=366).contains(&days));
    }

    #[test]
    fn cache_hit_returns_same_arc() {
        let f = forger();
        let a = f.forge("cached.example.com", &[]).unwrap();
        let b = f.forge("cached.example.com", &[]).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn cache_miss_for_different_domain() {
        let f = forger();
        let a = f.forge("a.example.com", &[]).unwrap();
        let b = f.forge("b.example.com", &[]).unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn cache_eviction_on_overflow() {
        let (cert_pem, key_pem) = make_ca();
        let f = CertForger::new(&cert_pem, &key_pem, 2).unwrap();

        f.forge("a.com", &[]).unwrap();
        f.forge("b.com", &[]).unwrap();
        f.forge("c.com", &[]).unwrap();

        let stats = f.cache_stats();
        assert_eq!(stats.size, 2);
    }

    #[test]
    fn cache_key_ignores_san_order() {
        let f = forger();
        let a = f
            .forge("main.com", &["a.com".into(), "b.com".into()])
            .unwrap();
        let b = f
            .forge("main.com", &["b.com".into(), "a.com".into()])
            .unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn cache_stats_tracking() {
        let f = forger();
        f.forge("x.com", &[]).unwrap();
        f.forge("x.com", &[]).unwrap();
        f.forge("y.com", &[]).unwrap();

        let stats = f.cache_stats();
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.size, 2);
        assert_eq!(stats.capacity, 100);
    }

    #[test]
    fn duplicate_san_not_repeated() {
        use x509_parser::extensions::GeneralName;
        let f = forger();
        let forged = f
            .forge("example.com", &["example.com".into(), "Example.COM".into()])
            .unwrap();
        let cert = parse_pem_cert(&forged.cert_pem);
        let san_ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .unwrap();
        let san = san_ext.parsed_extension();
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = san {
            let dns_names: Vec<&str> = san
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(s) => Some(*s),
                    _ => None,
                })
                .collect();
            assert_eq!(dns_names.len(), 1);
            assert_eq!(dns_names[0], "example.com");
        } else {
            panic!("SAN extension not found");
        }
    }
}
