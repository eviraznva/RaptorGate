use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, bail};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hkdf::{Salt, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};

const MACHINE_ID_PATH: &str = "/etc/machine-id";

// Odczytuje machine-id z systemu operacyjnego.
fn read_machine_id() -> anyhow::Result<Vec<u8>> {
    let id = fs::read_to_string(MACHINE_ID_PATH)
        .context("Failed to read /etc/machine-id")?;
    Ok(id.trim().as_bytes().to_vec())
}

struct AesKey256;

impl ring::hkdf::KeyType for AesKey256 {
    fn len(&self) -> usize {
        32
    }
}

// Wyznacza 32-bajtowy klucz AES-256 metodą HKDF-SHA256 z machine-id.
pub fn derive_encryption_key(machine_id: &[u8]) -> anyhow::Result<[u8; 32]> {
    let salt = Salt::new(HKDF_SHA256, b"raptorgate-ca-key-v1");
    let prk = salt.extract(machine_id);
    let mut key = [0u8; 32];
    prk.expand(&[b"aes-key".as_ref()], AesKey256)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?
        .fill(&mut key)
        .map_err(|_| anyhow::anyhow!("HKDF fill failed"))?;
    Ok(key)
}

// Szyfruje dane kluczem AES-256-GCM; losowy nonce (12 B) poprzedza szyfrogram.
pub fn encrypt_pem(plaintext: &[u8], key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to generate nonce"))?;

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| anyhow::anyhow!("Invalid AES key"))?;
    let aead_key = LessSafeKey::new(unbound);

    let mut data = plaintext.to_vec();
    aead_key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::empty(),
            &mut data,
        )
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    let mut result = Vec::with_capacity(NONCE_LEN + data.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&data);
    Ok(result)
}

// Deszyfruje dane zaszyfrowane przez encrypt_pem (nonce || szyfrogram || tag).
pub fn decrypt_pem(data: &[u8], key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    if data.len() < NONCE_LEN {
        bail!("Data too short — missing nonce");
    }

    let (nonce_slice, ciphertext) = data.split_at(NONCE_LEN);
    let nonce_bytes: [u8; NONCE_LEN] = nonce_slice.try_into().unwrap();

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| anyhow::anyhow!("Invalid AES key"))?;
    let aead_key = LessSafeKey::new(unbound);

    let mut buf = ciphertext.to_vec();
    let plaintext = aead_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::empty(),
            &mut buf,
        )
        .map_err(|_| anyhow::anyhow!("AES-GCM decryption failed"))?;
    Ok(plaintext.to_vec())
}

// Zapisuje zaszyfrowany klucz prywatny CA, certyfikat i metadane na dysk.
pub fn save_ca(
    dir: &Path,
    key_pem: &str,
    cert_pem: &str,
    fingerprint: &str,
    expires_at_secs: i64,
) -> anyhow::Result<()> {
    fs::create_dir_all(dir).context("Failed to create PKI directory")?;

    let machine_id = read_machine_id()?;
    let enc_key = derive_encryption_key(&machine_id)?;
    let encrypted = encrypt_pem(key_pem.as_bytes(), &enc_key)?;

    let key_path = dir.join("ca.key.enc");
    let cert_path = dir.join("ca.crt");
    let meta_path = dir.join("ca.meta.json");

    fs::write(&key_path, &encrypted).context("Failed to write ca.key.enc")?;
    fs::write(&cert_path, cert_pem).context("Failed to write ca.crt")?;

    let meta = serde_json::json!({
        "fingerprint": fingerprint,
        "expires_at_secs": expires_at_secs,
    });
    fs::write(&meta_path, meta.to_string()).context("Failed to write ca.meta.json")?;

    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .context("Failed to set permissions on ca.key.enc")?;
    fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644))
        .context("Failed to set permissions on ca.crt")?;
    fs::set_permissions(&meta_path, fs::Permissions::from_mode(0o644))
        .context("Failed to set permissions on ca.meta.json")?;

    Ok(())
}

// Struktura przechowująca metadane CA wczytane z dysku.
pub struct LoadedCa {
    pub key_pem: String,
    pub cert_pem: String,
    pub fingerprint: String,
    pub expires_at_secs: i64,
}

// Wczytuje certyfikat, odszyfrowany klucz prywatny i metadane CA z dysku. Zwraca None gdy pliki nie istnieją.
pub fn load_ca(dir: &Path) -> anyhow::Result<Option<LoadedCa>> {
    let key_path = dir.join("ca.key.enc");
    let cert_path = dir.join("ca.crt");
    let meta_path = dir.join("ca.meta.json");

    if !key_path.exists() || !cert_path.exists() || !meta_path.exists() {
        return Ok(None);
    }

    let machine_id = read_machine_id()?;
    let enc_key = derive_encryption_key(&machine_id)?;

    let encrypted = fs::read(&key_path).context("Failed to read ca.key.enc")?;
    let key_bytes = decrypt_pem(&encrypted, &enc_key)?;
    let key_pem =
        String::from_utf8(key_bytes).context("ca.key.enc contains invalid UTF-8")?;

    let cert_pem = fs::read_to_string(&cert_path).context("Failed to read ca.crt")?;

    let meta_str =
        fs::read_to_string(&meta_path).context("Failed to read ca.meta.json")?;
    let meta: serde_json::Value =
        serde_json::from_str(&meta_str).context("Failed to parse ca.meta.json")?;

    let fingerprint = meta["fingerprint"]
        .as_str()
        .context("Missing field 'fingerprint' in ca.meta.json")?
        .to_string();
    let expires_at_secs = meta["expires_at_secs"]
        .as_i64()
        .context("Missing field 'expires_at_secs' in ca.meta.json")?;

    Ok(Some(LoadedCa {
        key_pem,
        cert_pem,
        fingerprint,
        expires_at_secs,
    }))
}
