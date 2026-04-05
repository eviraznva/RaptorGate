use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use dashmap::DashMap;
use ring::digest::{digest, SHA256};
use rustls::ServerConfig;
use super::rustls_config::build_server_config_from_pem;
use super::server_key_storage;

// Wpis inbound TLS dla jednego serwera.
struct InboundServerEntry {
    server_config: Arc<ServerConfig>,
    common_name: String,
    fingerprint: String,
}

// Informacja o zarejestrowanym serwerze inbound (publiczne DTO).
#[derive(Debug, Clone)]
pub struct InboundServerInfo {
    pub addr: SocketAddr,
    pub common_name: String,
    pub fingerprint: String,
}

// Rejestr kluczy serwerow do inspekcji inbound TLS.
pub struct ServerKeyStore {
    entries: DashMap<SocketAddr, InboundServerEntry>,
    pki_dir: String,
}

impl ServerKeyStore {
    pub fn new(pki_dir: &str) -> Self {
        Self {
            entries: DashMap::new(),
            pki_dir: pki_dir.to_string(),
        }
    }

    // Rejestruje klucz serwera: zapisuje na dysk i buduje ServerConfig.
    pub fn add(
        &self,
        addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
        key_ref: &str,
        common_name: &str,
        fingerprint: &str,
    ) -> anyhow::Result<()> {
        server_key_storage::save_server_key(Path::new(&self.pki_dir), key_ref, key_pem)
            .with_context(|| format!("Failed to persist server key for {addr}"))?;

        let server_config = build_server_config_from_pem(cert_pem, key_pem)
            .with_context(|| format!("Failed to build TLS config for {addr}"))?;

        self.entries.insert(
            addr,
            InboundServerEntry {
                server_config,
                common_name: common_name.to_string(),
                fingerprint: fingerprint.to_string(),
            },
        );

        tracing::info!(%addr, cn = common_name, "Inbound TLS server key registered");
        Ok(())
    }

    // Laduje klucz serwera z dysku (przy starcie firewalla).
    pub fn load(
        &self,
        addr: SocketAddr,
        cert_pem: &str,
        key_ref: &str,
        common_name: &str,
        fingerprint: &str,
    ) -> anyhow::Result<()> {
        let key_pem = server_key_storage::load_server_key(Path::new(&self.pki_dir), key_ref)
            .with_context(|| format!("Failed to load server key {key_ref}"))?;

        let server_config = build_server_config_from_pem(cert_pem, &key_pem)
            .with_context(|| format!("Failed to build TLS config for {addr}"))?;

        self.entries.insert(
            addr,
            InboundServerEntry {
                server_config,
                common_name: common_name.to_string(),
                fingerprint: fingerprint.to_string(),
            },
        );

        tracing::info!(%addr, cn = common_name, "Inbound TLS server key loaded from disk");
        Ok(())
    }

    // Zwraca ServerConfig dla danego adresu (jesli zarejestrowany).
    pub fn get(&self, addr: SocketAddr) -> Option<Arc<ServerConfig>> {
        self.entries
            .get(&addr)
            .map(|entry| Arc::clone(&entry.server_config))
    }

    // Sprawdza czy adres ma zarejestrowany klucz inbound.
    pub fn contains(&self, ip: IpAddr, port: u16) -> bool {
        self.entries.contains_key(&SocketAddr::new(ip, port))
    }

    // Usuwa klucz serwera z rejestru i z dysku.
    pub fn remove(&self, addr: SocketAddr, key_ref: &str) -> anyhow::Result<bool> {
        let removed = self.entries.remove(&addr).is_some();
        if removed {
            server_key_storage::delete_server_key(Path::new(&self.pki_dir), key_ref)?;
            tracing::info!(%addr, "Inbound TLS server key removed");
        }
        Ok(removed)
    }

    // Zwraca liste zarejestrowanych serwerow inbound.
    pub fn list(&self) -> Vec<InboundServerInfo> {
        self.entries
            .iter()
            .map(|entry| InboundServerInfo {
                addr: *entry.key(),
                common_name: entry.value().common_name.clone(),
                fingerprint: entry.value().fingerprint.clone(),
            })
            .collect()
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};
    use std::net::Ipv4Addr;

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

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 10)), 443)
    }

    #[test]
    fn add_and_get() {
        let dir = temp_dir();
        let store = ServerKeyStore::new(&dir);
        let (cert, key) = make_server_cert();
        let addr = test_addr();

        store
            .add(addr, &cert, &key, "test-ref-001", "test-server.local", "AA:BB")
            .unwrap();

        assert!(store.get(addr).is_some());
        assert_eq!(store.count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn get_missing_returns_none() {
        let dir = temp_dir();
        let store = ServerKeyStore::new(&dir);

        assert!(store.get(test_addr()).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn contains_check() {
        let dir = temp_dir();
        let store = ServerKeyStore::new(&dir);
        let (cert, key) = make_server_cert();
        let addr = test_addr();

        store
            .add(addr, &cert, &key, "test-ref-002", "test-server.local", "AA:BB")
            .unwrap();

        assert!(store.contains(addr.ip(), addr.port()));
        assert!(!store.contains(addr.ip(), 8443));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_entry() {
        let dir = temp_dir();
        let store = ServerKeyStore::new(&dir);
        let (cert, key) = make_server_cert();
        let addr = test_addr();

        store
            .add(addr, &cert, &key, "test-ref-003", "test-server.local", "AA:BB")
            .unwrap();
        assert!(store.get(addr).is_some());

        let removed = store.remove(addr, "test-ref-003").unwrap();
        assert!(removed);
        assert!(store.get(addr).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_entries() {
        let dir = temp_dir();
        let store = ServerKeyStore::new(&dir);
        let (cert, key) = make_server_cert();

        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8443);

        store
            .add(addr1, &cert, &key, "ref-a", "server-a", "AA:AA")
            .unwrap();
        store
            .add(addr2, &cert, &key, "ref-b", "server-b", "BB:BB")
            .unwrap();

        let list = store.list();
        assert_eq!(list.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_from_disk() {
        let dir = temp_dir();
        let store = ServerKeyStore::new(&dir);
        let (cert, key) = make_server_cert();
        let addr = test_addr();

        server_key_storage::save_server_key(Path::new(&dir), "disk-ref", &key).unwrap();

        store
            .load(addr, &cert, "disk-ref", "test-server.local", "CC:DD")
            .unwrap();

        assert!(store.get(addr).is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
