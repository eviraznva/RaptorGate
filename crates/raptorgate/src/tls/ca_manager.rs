use std::path::Path;

use anyhow::Context;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use ring::digest::{digest, SHA256};
use time::OffsetDateTime;

use crate::tls::cert_storage;

// Informacje o CA przekazywane do control plane.
#[derive(Clone)]
pub struct CaInfo {
    pub cert_pem: String,
    pub fingerprint: String,
    pub expires_at: prost_types::Timestamp,
}

// Zarządca certyfikatów CA, trust + untrust.
pub struct CaManager {
    ca_cert_pem: String,
    ca_key_pem: String,
    fingerprint: String,
    expires_at: prost_types::Timestamp,
    untrust_cert_pem: String,
    untrust_key_pem: String,
    untrust_fingerprint: String,
}

impl CaManager {
    // Ładuje istniejące CA z dysku lub generuje nowe i zapisuje je na dysk.
    pub fn init(pki_dir: &str) -> anyhow::Result<Self> {
        let dir = Path::new(pki_dir);

        let (ca_cert_pem, ca_key_pem, fingerprint, expires_at) =
            if let Some(loaded) = cert_storage::load_ca(dir)? {
                tracing::info!(pki_dir, "Loaded existing CA from disk");
                (
                    loaded.cert_pem,
                    loaded.key_pem,
                    loaded.fingerprint,
                    prost_types::Timestamp { seconds: loaded.expires_at_secs, nanos: 0 },
                )
            } else {
                tracing::info!(pki_dir, "Generating new CA certificate");
                let generated = generate_ca("RaptorGate CA")?;
                cert_storage::save_ca(
                    dir, &generated.key_pem, &generated.cert_pem,
                    &generated.fingerprint, generated.expires_at.seconds,
                )?;
                tracing::info!(fingerprint = %generated.fingerprint, "New CA generated and saved");
                (generated.cert_pem, generated.key_pem, generated.fingerprint, generated.expires_at)
            };

        let (untrust_cert_pem, untrust_key_pem, untrust_fingerprint) =
            if let Some(loaded) = cert_storage::load_untrust_ca(dir)? {
                tracing::info!(pki_dir, "Loaded existing Untrust CA from disk");
                (loaded.cert_pem, loaded.key_pem, loaded.fingerprint)
            } else {
                tracing::info!(pki_dir, "Generating new Untrust CA certificate");
                let generated = generate_ca("RaptorGate Untrust CA")?;
                cert_storage::save_untrust_ca(
                    dir, &generated.key_pem, &generated.cert_pem,
                    &generated.fingerprint, generated.expires_at.seconds,
                )?;
                tracing::info!(fingerprint = %generated.fingerprint, "Untrust CA generated and saved");
                (generated.cert_pem, generated.key_pem, generated.fingerprint)
            };

        Ok(Self {
            ca_cert_pem, ca_key_pem, fingerprint, expires_at,
            untrust_cert_pem, untrust_key_pem, untrust_fingerprint,
        })
    }

    // Tworzy CertForger podpisujący certyfikaty tym CA.
    pub fn cert_forger(&self, cache_capacity: usize) -> anyhow::Result<super::CertForger> {
        super::CertForger::new(&self.ca_cert_pem, &self.ca_key_pem, cache_capacity)
    }

    // Tworzy CertForger podpisujący certyfikaty Untrust CA.
    pub fn untrust_cert_forger(&self, cache_capacity: usize) -> anyhow::Result<super::CertForger> {
        super::CertForger::new(&self.untrust_cert_pem, &self.untrust_key_pem, cache_capacity)
    }

    // Zwraca informacje o CA do przekazania do control plane.
    pub fn ca_info(&self) -> CaInfo {
        CaInfo {
            cert_pem: self.ca_cert_pem.clone(),
            fingerprint: self.fingerprint.clone(),
            expires_at: self.expires_at.clone(),
        }
    }
}

struct GeneratedCa {
    key_pem: String,
    cert_pem: String,
    fingerprint: String,
    expires_at: prost_types::Timestamp,
}

// Generuje nową parę klucz/certyfikat CA ważną 10 lat.
fn generate_ca(common_name: &str) -> anyhow::Result<GeneratedCa> {
    let key_pair = KeyPair::generate().context("Failed to generate CA key pair")?;

    let now = OffsetDateTime::now_utc();
    let expiry = now + time::Duration::days(3650);

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = now;
    params.not_after = expiry;
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "RaptorGate");

    let cert = params
        .self_signed(&key_pair)
        .context("Failed to self-sign CA certificate")?;

    let fingerprint = compute_fingerprint(cert.der().as_ref());
    let expires_at = prost_types::Timestamp {
        seconds: expiry.unix_timestamp(),
        nanos: 0,
    };

    Ok(GeneratedCa {
        key_pem: key_pair.serialize_pem(),
        cert_pem: cert.pem(),
        fingerprint,
        expires_at,
    })
}

// Oblicza odcisk palca SHA-256 z bajtów DER certyfikatu w formacie XX:XX:...
pub fn compute_fingerprint(der: &[u8]) -> String {
    let hash = digest(&SHA256, der);
    hash.as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Sprawdza czy init generuje nowe CA gdy katalog jest pusty.
    #[test]
    fn init_generates_new_ca() {
        let dir = temp_dir();
        let manager = CaManager::init(dir.to_str().unwrap()).unwrap();
        let info = manager.ca_info();

        assert!(info.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!info.fingerprint.is_empty());
        assert!(info.expires_at.seconds > 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Sprawdza czy ponowne init wczytuje to samo CA z dysku.
    #[test]
    fn init_loads_existing_ca() {
        let dir = temp_dir();
        let pki_dir = dir.to_str().unwrap();

        let first = CaManager::init(pki_dir).unwrap();
        let second = CaManager::init(pki_dir).unwrap();

        assert_eq!(first.ca_info().fingerprint, second.ca_info().fingerprint);
        assert_eq!(first.ca_info().cert_pem, second.ca_info().cert_pem);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Sprawdza czy fingerprint ma format 32 bajtow hex oddzielonych dwukropkiem.
    #[test]
    fn fingerprint_has_correct_format() {
        let dir = temp_dir();
        let manager = CaManager::init(dir.to_str().unwrap()).unwrap();
        let info = manager.ca_info();
        let parts: Vec<&str> = info.fingerprint.split(':').collect();

        assert_eq!(parts.len(), 32);
        for part in parts {
            assert_eq!(part.len(), 2);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Sprawdza czy CA jest wazne okolo 10 lat.
    #[test]
    fn ca_expires_in_roughly_10_years() {
        let dir = temp_dir();
        let manager = CaManager::init(dir.to_str().unwrap()).unwrap();
        let expires = manager.ca_info().expires_at.seconds;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let years = (expires - now) / (365 * 24 * 3600);
        assert!((9..=10).contains(&years));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Sprawdza czy compute_fingerprint zwraca ten sam wynik dla tych samych danych.
    #[test]
    fn compute_fingerprint_is_deterministic() {
        let data = b"test certificate bytes";
        let fp1 = compute_fingerprint(data);
        let fp2 = compute_fingerprint(data);
        assert_eq!(fp1, fp2);
    }

    // Sprawdza czy compute_fingerprint zwraca rozny wynik dla roznych danych.
    #[test]
    fn compute_fingerprint_differs_for_different_input() {
        let fp1 = compute_fingerprint(b"cert A");
        let fp2 = compute_fingerprint(b"cert B");
        assert_ne!(fp1, fp2);
    }
}
