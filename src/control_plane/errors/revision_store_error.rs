use crate::policy::rgpf::errors::rgpf_error::RgpfError;

/// Błędy ładowania rewizji z magazynu konfiguracji.
#[derive(Debug, thiserror::Error)]
pub enum RevisionStoreError {
    #[error("failed to read active symlink: {0}")]
    ReadActiveLink(#[source] std::io::Error),

    #[error("active symlink must point to versions/<revision>, found: {target}")]
    InvalidActiveTarget { target: String },

    #[error("active revision directory is not a valid u64: {name}")]
    InvalidRevisionDirectory { name: String },

    #[error("failed to read policy.bin: {0}")]
    ReadPolicy(#[source] std::io::Error),

    #[error("failed to parse rgpf: {0}")]
    ParseRgpf(#[from] RgpfError),

    #[error("active revision mismatch: expected {expected}, found {found}")]
    RevisionMismatch { expected: u64, found: u64 },
}
