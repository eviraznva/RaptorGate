use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use dashmap::DashMap;
use rustls::ServerConfig;

use super::cert_storage::{decrypt_pem, encrypt_pem, read_encryption_key};
use super::rustls_config::build_server_config_from_pem;

use serde::{Deserialize, Serialize};

const SERVER_KEYS_DIR: &str = "server_keys";

// Metadane serwera inbound, persystowane obok zaszyfrowanego klucza.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerKeyMeta {
    addr: String,
    port: u16,
    common_name: String,
    fingerprint: String,
    certificate_pem: String,
    key_ref: String,
    bypass: bool,
}

fn key_path(pki_dir: &Path, id: &str) -> PathBuf {
    pki_dir.join(SERVER_KEYS_DIR).join(format!("{id}.key.enc"))
}

fn meta_path(pki_dir: &Path, id: &str) -> PathBuf {
    pki_dir.join(SERVER_KEYS_DIR).join(format!("{id}.meta.json"))
}

fn save_meta(pki_dir: &Path, id: &str, meta: &ServerKeyMeta) -> anyhow::Result<()> {
    let path = meta_path(pki_dir, id);
    let json = serde_json::to_string_pretty(meta)?;
    fs::write(&path, json).with_context(|| format!("Failed to write meta for {id}"))?;
    Ok(())
}

fn delete_meta(pki_dir: &Path, id: &str) {
    let path = meta_path(pki_dir, id);
    let _ = fs::remove_file(path);
}

fn save_key_to_disk(pki_dir: &Path, id: &str, key_pem: &str) -> anyhow::Result<()> {
    let dir = pki_dir.join(SERVER_KEYS_DIR);
    fs::create_dir_all(&dir).context("Failed to create server_keys directory")?;

    let enc_key = read_encryption_key()?;
    let encrypted = encrypt_pem(key_pem.as_bytes(), &enc_key)?;

    let path = key_path(pki_dir, id);
    fs::write(&path, &encrypted)
        .with_context(|| format!("Failed to write server key {id}"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set permissions on server key {id}"))?;

    Ok(())
}

fn load_key_from_disk(pki_dir: &Path, id: &str) -> anyhow::Result<String> {
    let path = key_path(pki_dir, id);
    let encrypted =
        fs::read(&path).with_context(|| format!("Failed to read server key {id}"))?;

    let enc_key = read_encryption_key()?;
    let decrypted = decrypt_pem(&encrypted, &enc_key)?;

    String::from_utf8(decrypted).context("Server key contains invalid UTF-8")
}

fn delete_key_from_disk(pki_dir: &Path, id: &str) -> anyhow::Result<()> {
    let path = key_path(pki_dir, id);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("Failed to delete server key {id}"))?;
    }
    Ok(())
}

// Wpis inbound TLS dla jednego serwera.
struct InboundServerEntry {
    server_config: Arc<ServerConfig>,
    common_name: String,
    fingerprint: String,
    bypass: bool,
}

// Informacja o zarejestrowanym serwerze inbound (publiczne DTO).
#[derive(Debug, Clone)]
pub struct InboundServerInfo {
    pub addr: SocketAddr,
    pub common_name: String,
    pub fingerprint: String,
    pub bypass: bool,
}

// Wynik get_entry, ServerConfig + flaga bypass.
pub struct InboundEntryRef {
    pub server_config: Arc<ServerConfig>,
    pub common_name: String,
    pub bypass: bool,
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

    // Rejestruje klucz serwera: zapisuje klucz + meta na dysk i buduje ServerConfig.
    pub fn add(
        &self,
        addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
        key_ref: &str,
        common_name: &str,
        fingerprint: &str,
        bypass: bool,
    ) -> anyhow::Result<()> {
        let pki = Path::new(&self.pki_dir);
        save_key_to_disk(pki, key_ref, key_pem)
            .with_context(|| format!("Failed to persist server key for {addr}"))?;

        save_meta(pki, key_ref, &ServerKeyMeta {
            addr: addr.ip().to_string(),
            port: addr.port(),
            common_name: common_name.to_string(),
            fingerprint: fingerprint.to_string(),
            certificate_pem: cert_pem.to_string(),
            key_ref: key_ref.to_string(),
            bypass,
        })?;

        let server_config = build_server_config_from_pem(cert_pem, key_pem)
            .with_context(|| format!("Failed to build TLS config for {addr}"))?;

        self.entries.insert(
            addr,
            InboundServerEntry {
                server_config,
                common_name: common_name.to_string(),
                fingerprint: fingerprint.to_string(),
                bypass,
            },
        );

        tracing::info!(%addr, cn = common_name, bypass, "Inbound TLS server key registered");
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
        bypass: bool,
    ) -> anyhow::Result<()> {
        let key_pem = load_key_from_disk(Path::new(&self.pki_dir), key_ref)
            .with_context(|| format!("Failed to load server key {key_ref}"))?;

        let server_config = build_server_config_from_pem(cert_pem, &key_pem)
            .with_context(|| format!("Failed to build TLS config for {addr}"))?;

        self.entries.insert(
            addr,
            InboundServerEntry {
                server_config,
                common_name: common_name.to_string(),
                fingerprint: fingerprint.to_string(),
                bypass,
            },
        );

        tracing::info!(%addr, cn = common_name, bypass, "Inbound TLS server key loaded from disk");
        Ok(())
    }

    // Zwraca ServerConfig dla danego adresu (jesli zarejestrowany).
    pub fn get(&self, addr: SocketAddr) -> Option<Arc<ServerConfig>> {
        self.entries
            .get(&addr)
            .map(|entry| Arc::clone(&entry.server_config))
    }

    // Zwraca ServerConfig + bypass dla danego adresu.
    pub fn get_entry(&self, addr: SocketAddr) -> Option<InboundEntryRef> {
        self.entries.get(&addr).map(|entry| InboundEntryRef {
            server_config: Arc::clone(&entry.server_config),
            common_name: entry.common_name.clone(),
            bypass: entry.bypass,
        })
    }

    // Sprawdza czy adres ma zarejestrowany klucz inbound.
    pub fn contains(&self, ip: IpAddr, port: u16) -> bool {
        self.entries.contains_key(&SocketAddr::new(ip, port))
    }

    // Usuwa klucz serwera z rejestru i z dysku (klucz + meta).
    pub fn remove(&self, addr: SocketAddr, key_ref: &str) -> anyhow::Result<bool> {
        let removed = self.entries.remove(&addr).is_some();
        if removed {
            let pki = Path::new(&self.pki_dir);
            delete_key_from_disk(pki, key_ref)?;
            delete_meta(pki, key_ref);
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
                bypass: entry.value().bypass,
            })
            .collect()
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }

    // Laduje wszystkie klucze serwerowe z dysku przy starcie (z meta.json).
    pub fn load_all_from_disk(&self) -> usize {
        let dir = Path::new(&self.pki_dir).join(SERVER_KEYS_DIR);
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return 0,
        };

        let mut count = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) if n.ends_with(".meta.json") => n.trim_end_matches(".meta.json").to_string(),
                _ => continue,
            };

            let meta_content = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(file = %path.display(), error = %e, "failed to read meta");
                    continue;
                }
            };

            let meta: ServerKeyMeta = match serde_json::from_str(&meta_content) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(file = %path.display(), error = %e, "failed to parse meta");
                    continue;
                }
            };

            let ip: IpAddr = match meta.addr.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    tracing::warn!(key_ref = %name, error = %e, "invalid addr in meta");
                    continue;
                }
            };

            let addr = SocketAddr::new(ip, meta.port);
            if let Err(e) = self.load(
                addr,
                &meta.certificate_pem,
                &meta.key_ref,
                &meta.common_name,
                &meta.fingerprint,
                meta.bypass,
            ) {
                tracing::warn!(key_ref = %name, error = %e, "failed to load server key from disk");
                continue;
            }
            count += 1;
        }

        if count > 0 {
            tracing::info!(count, "inbound TLS server keys loaded from disk");
        }
        count
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
            .add(addr, &cert, &key, "test-ref-001", "test-server.local", "AA:BB", false)
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
            .add(addr, &cert, &key, "test-ref-002", "test-server.local", "AA:BB", false)
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
            .add(addr, &cert, &key, "test-ref-003", "test-server.local", "AA:BB", false)
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
            .add(addr1, &cert, &key, "ref-a", "server-a", "AA:AA", false)
            .unwrap();
        store
            .add(addr2, &cert, &key, "ref-b", "server-b", "BB:BB", false)
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

        save_key_to_disk(Path::new(&dir), "disk-ref", &key).unwrap();

        store
            .load(addr, &cert, "disk-ref", "test-server.local", "CC:DD", false)
            .unwrap();

        assert!(store.get(addr).is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
