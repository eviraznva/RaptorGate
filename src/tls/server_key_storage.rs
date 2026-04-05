use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;

use super::cert_storage::{decrypt_pem, derive_encryption_key, encrypt_pem};

const SERVER_KEYS_DIR: &str = "server_keys";

// Zwraca sciezke do katalogu z kluczami serwerow.
fn keys_dir(pki_dir: &Path) -> PathBuf {
    pki_dir.join(SERVER_KEYS_DIR)
}

// Zwraca sciezke do zaszyfrowanego klucza serwera.
fn key_path(pki_dir: &Path, id: &str) -> PathBuf {
    keys_dir(pki_dir).join(format!("{id}.key.enc"))
}

// Odczytuje machine-id i zwraca klucz szyfrowania.
fn encryption_key() -> anyhow::Result<[u8; 32]> {
    let machine_id = fs::read_to_string("/etc/machine-id")
        .context("Failed to read /etc/machine-id")?;
    derive_encryption_key(machine_id.trim().as_bytes())
}

// Zapisuje zaszyfrowany klucz prywatny serwera na dysk.
pub fn save_server_key(pki_dir: &Path, id: &str, key_pem: &str) -> anyhow::Result<()> {
    let dir = keys_dir(pki_dir);
    fs::create_dir_all(&dir).context("Failed to create server_keys directory")?;

    let enc_key = encryption_key()?;
    let encrypted = encrypt_pem(key_pem.as_bytes(), &enc_key)?;

    let path = key_path(pki_dir, id);
    fs::write(&path, &encrypted)
        .with_context(|| format!("Failed to write server key {id}"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set permissions on server key {id}"))?;

    Ok(())
}

// Wczytuje i odszyfrowuje klucz prywatny serwera z dysku.
pub fn load_server_key(pki_dir: &Path, id: &str) -> anyhow::Result<String> {
    let path = key_path(pki_dir, id);
    let encrypted = fs::read(&path)
        .with_context(|| format!("Failed to read server key {id}"))?;

    let enc_key = encryption_key()?;
    let decrypted = decrypt_pem(&encrypted, &enc_key)?;

    String::from_utf8(decrypted).context("Server key contains invalid UTF-8")
}

// Usuwa zaszyfrowany klucz serwera z dysku.
pub fn delete_server_key(pki_dir: &Path, id: &str) -> anyhow::Result<()> {
    let path = key_path(pki_dir, id);
    if path.exists() {
        fs::remove_file(&path)
            .with_context(|| format!("Failed to delete server key {id}"))?;
    }
    Ok(())
}

// Sprawdza czy klucz serwera istnieje na dysku.
pub fn server_key_exists(pki_dir: &Path, id: &str) -> bool {
    key_path(pki_dir, id).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir()
            .join(uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = temp_dir();
        let key_pem = "-----BEGIN PRIVATE KEY-----\nfake-server-key\n-----END PRIVATE KEY-----\n";

        save_server_key(&dir, "srv-001", key_pem).unwrap();
        let loaded = load_server_key(&dir, "srv-001").unwrap();

        assert_eq!(loaded, key_pem);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn key_file_has_restricted_permissions() {
        let dir = temp_dir();
        save_server_key(&dir, "srv-002", "key-data").unwrap();

        let mode = fs::metadata(key_path(&dir, "srv-002"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_nonexistent_returns_error() {
        let dir = temp_dir();
        assert!(load_server_key(&dir, "nonexistent").is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_removes_file() {
        let dir = temp_dir();
        save_server_key(&dir, "srv-003", "key-data").unwrap();
        assert!(server_key_exists(&dir, "srv-003"));

        delete_server_key(&dir, "srv-003").unwrap();
        assert!(!server_key_exists(&dir, "srv-003"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn delete_nonexistent_is_ok() {
        let dir = temp_dir();
        assert!(delete_server_key(&dir, "ghost").is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn server_key_exists_check() {
        let dir = temp_dir();
        assert!(!server_key_exists(&dir, "srv-004"));

        save_server_key(&dir, "srv-004", "key").unwrap();
        assert!(server_key_exists(&dir, "srv-004"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
