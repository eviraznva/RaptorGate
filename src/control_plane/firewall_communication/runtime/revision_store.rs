use std::sync::Arc;
use tracing::{debug, info, trace, warn};
use std::path::{Component, Path, PathBuf};

use crate::control_plane::logging::payload_preview_hex;
use crate::policy::rgpf::sections::rgpf_file::RgpfFile;
use crate::policy::rgpf::load::compiled_policy::load_compiled_policy_bundle;
use crate::control_plane::errors::revision_store_error::RevisionStoreError;
use crate::control_plane::firewall_communication::runtime::state::ActiveRevision;

/// Reader magazynu rewizji po stronie firewalla.
#[derive(Debug, Clone)]
pub struct RevisionStore {
    root: PathBuf,
}

impl RevisionStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();

        debug!(config_store_path = %root.display(), "Created revision store reader");

        Self { root }
    }

    #[tracing::instrument(skip(self), fields(config_store_path = %self.root.display(), expected_revision_id))]
    pub async fn load_active_revision(&self, expected_revision_id: u64) -> Result<Arc<ActiveRevision>, RevisionStoreError> {
        debug!(
            config_store_path = %self.root.display(),
            expected_revision_id,
            "Loading active revision from config store"
        );

        let (revision_id_from_target, active_target) = self.resolve_active_target().await?;

        if revision_id_from_target != expected_revision_id {
            warn!(
                config_store_path = %self.root.display(),
                expected_revision_id,
                revision_id_from_target,
                active_target = %active_target.display(),
                "Revision id from active symlink target does not match requested revision"
            );
            
            return Err(RevisionStoreError::RevisionMismatch {
                expected: expected_revision_id,
                found: revision_id_from_target,
            });
        }

        self.load_revision_from_target(active_target, expected_revision_id).await
    }

    #[tracing::instrument(skip(self), fields(config_store_path = %self.root.display()))]
    pub async fn load_current_active_revision(&self) -> Result<Arc<ActiveRevision>, RevisionStoreError> 
    {
        debug!(
            config_store_path = %self.root.display(),
            "Loading current active revision from config store"
        );

        let (revision_id_from_target, active_target) = self.resolve_active_target().await?;

        self.load_revision_from_target(active_target, revision_id_from_target).await
    }

    #[tracing::instrument(skip(self), fields(config_store_path = %self.root.display()))]
    async fn resolve_active_target(&self) -> Result<(u64, PathBuf), RevisionStoreError> {
        let active_link = self.root.join("active");

        trace!(active_link = %active_link.display(), "Resolving active revision symlink");

        let active_target = tokio::fs::read_link(&active_link).await
            .map_err(RevisionStoreError::ReadActiveLink)?;

        let revision_id_from_target = parse_active_revision_target(&active_target)?;

        debug!(
            active_link = %active_link.display(),
            active_target = %active_target.display(),
            revision_id = revision_id_from_target,
            "Resolved active revision symlink"
        );

        Ok((revision_id_from_target, active_target))
    }

    #[tracing::instrument(skip(self), fields(expected_revision_id))]
    async fn load_revision_from_target(
        &self,
        active_target: PathBuf,
        expected_revision_id: u64,
    ) -> Result<Arc<ActiveRevision>, RevisionStoreError> {
        let revision_dir = if active_target.is_absolute() {
            active_target
        } else {
            self.root.join(active_target)
        };

        let policy_path = revision_dir.join("policy.bin");

        trace!(
            revision_dir = %revision_dir.display(),
            policy_path = %policy_path.display(),
            expected_revision_id,
            "Loading policy.bin for active revision"
        );

        let bytes = tokio::fs::read(&policy_path).await
            .map_err(RevisionStoreError::ReadPolicy)?;

        trace!(
            policy_path = %policy_path.display(),
            file_len = bytes.len(),
            payload_preview_hex = %payload_preview_hex(&bytes, 32),
            "Read policy.bin bytes from config store"
        );

        let bytes: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());

        let file = RgpfFile::parse(bytes.as_ref())?;

        let actual_revision_id = file.header().revision_id.get();

        if actual_revision_id != expected_revision_id {
            warn!(
                policy_path = %policy_path.display(),
                expected_revision_id,
                actual_revision_id,
                "RGPF header revision id does not match expected revision"
            );
            
            return Err(RevisionStoreError::RevisionMismatch {
                expected: expected_revision_id,
                found: actual_revision_id,
            });
        }

        let policy_hash = file.header().policy_hash.get();
        
        let compiled_policy_bundle = Arc::new(load_compiled_policy_bundle(&file)?);
        
        let policy_count = compiled_policy_bundle.metadata().policy_count;

        info!(
            revision_id = actual_revision_id,
            policy_hash,
            policy_count,
            policy_path = %policy_path.display(),
            "Loaded active policy revision from config store"
        );

        Ok(Arc::new(ActiveRevision::from_rgpf(
            bytes,
            compiled_policy_bundle,
            actual_revision_id,
            policy_hash,
            policy_count,
        )))
    }
}

fn parse_active_revision_target(target: &Path) -> Result<u64, RevisionStoreError> {
    trace!(active_target = %target.display(), "Parsing active revision symlink target");

    let mut components = target.components().rev();

    let revision_component = components.next()
        .ok_or_else(|| RevisionStoreError::InvalidActiveTarget {
            target: target.display().to_string(),
        })?;

    let versions_component = components.next()
        .ok_or_else(|| RevisionStoreError::InvalidActiveTarget {
            target: target.display().to_string(),
        })?;

    let revision_name = match revision_component {
        Component::Normal(name) => name.to_string_lossy().to_string(),
        _ => {
            return Err(RevisionStoreError::InvalidActiveTarget {
                target: target.display().to_string(),
            });
        }
    };

    match versions_component {
        Component::Normal(name) if name == "versions" => {}
        _ => {
            return Err(RevisionStoreError::InvalidActiveTarget {
                target: target.display().to_string(),
            });
        }
    }

    revision_name.parse::<u64>().map_err(|_| RevisionStoreError::InvalidRevisionDirectory {
        name: revision_name,
    })
}

#[cfg(test)]
mod revision_store_tests {
    use tokio::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{parse_active_revision_target, RevisionStore};

    use crate::control_plane::errors::revision_store_error::RevisionStoreError;
    
    use crate::policy::rgpf::test_helpers::{
        TEST_POLICY_HASH, TEST_POLICY_SOURCE,
        build_policy_bin, build_policy_bin_with_invalid_nat
    };

    static NEXT_TEST_DIR_ID: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn parse_active_target_accepts_relative_versions_path() {
        let revision = parse_active_revision_target(Path::new("versions/320")).unwrap();

        assert_eq!(revision, 320);
    }

    #[test]
    fn parse_active_target_accepts_absolute_versions_path() {
        let revision = parse_active_revision_target(Path::new("/etc/raptorgate/config/runtime/versions/320")).unwrap();

        assert_eq!(revision, 320);
    }

    #[test]
    fn parse_active_target_rejects_non_numeric_revision() {
        let err = parse_active_revision_target(Path::new("versions/latest")).unwrap_err();

        assert!(matches!(err, RevisionStoreError::InvalidRevisionDirectory { .. }));
    }

    #[test]
    fn parse_active_target_rejects_path_outside_versions_dir() {
        let err = parse_active_revision_target(Path::new("current/320")).unwrap_err();

        assert!(matches!(err, RevisionStoreError::InvalidActiveTarget { .. }));
    }

    #[tokio::test]
    async fn load_active_revision_reads_versions_symlink_and_policy() {
        let root = create_test_dir();
        
        let versions_dir = root.join("versions");
        
        let revision_dir = versions_dir.join("320");
        
        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();
        fs::write(revision_dir.join("policy.bin"), build_policy_bin(320, TEST_POLICY_SOURCE)).await.unwrap();
        
        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let store = RevisionStore::new(&root);

        let revision = store.load_active_revision(320).await.unwrap();

        assert_eq!(revision.revision_id(), 320);
        assert_eq!(revision.policy_hash(), TEST_POLICY_HASH);
        assert_eq!(revision.policy_count(), 1);
        assert!(revision.rgpf().unwrap().is_some());
    }

    #[tokio::test]
    async fn load_current_active_revision_reads_revision_from_target() {
        let root = create_test_dir();
        
        let versions_dir = root.join("versions");
        
        let revision_dir = versions_dir.join("320");
        
        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();
        
        fs::write(revision_dir.join("policy.bin"), build_policy_bin(320, TEST_POLICY_SOURCE)).await.unwrap();
        
        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let store = RevisionStore::new(&root);

        let revision = store.load_current_active_revision().await.unwrap();

        assert_eq!(revision.revision_id(), 320);
        assert_eq!(revision.policy_hash(), TEST_POLICY_HASH);
    }

    #[tokio::test]
    async fn load_active_revision_rejects_target_revision_mismatch() {
        let root = create_test_dir();
        
        let versions_dir = root.join("versions");
        
        let revision_dir = versions_dir.join("320");
        
        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();
        
        fs::write(revision_dir.join("policy.bin"), build_policy_bin(320, TEST_POLICY_SOURCE)).await.unwrap();
        
        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let store = RevisionStore::new(&root);

        let result = store.load_active_revision(321).await;

        assert!(matches!(result, Err(RevisionStoreError::RevisionMismatch { expected: 321, found: 320 })));
    }

    #[tokio::test]
    async fn load_active_revision_rejects_invalid_active_target() {
        let root = create_test_dir();
        
        let current_dir = root.join("current").join("320");
        
        let active_link = root.join("active");

        fs::create_dir_all(&current_dir).await.unwrap();
        
        fs::write(current_dir.join("policy.bin"), build_policy_bin(320, TEST_POLICY_SOURCE)).await.unwrap();
        
        #[cfg(unix)]
        std::os::unix::fs::symlink("current/320", &active_link).unwrap();

        let store = RevisionStore::new(&root);

        let result = store.load_active_revision(320).await;

        assert!(matches!(result, Err(RevisionStoreError::InvalidActiveTarget { .. })));
    }

    #[tokio::test]
    async fn load_active_revision_rejects_invalid_nat_section() {
        let root = create_test_dir();

        let versions_dir = root.join("versions");
        let revision_dir = versions_dir.join("320");
        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();
        fs::write(
            revision_dir.join("policy.bin"),
            build_policy_bin_with_invalid_nat(320, TEST_POLICY_SOURCE),
        )
        .await
        .unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let store = RevisionStore::new(&root);

        let result = store.load_active_revision(320).await;

        assert!(matches!(
            result,
            Err(RevisionStoreError::ParseRgpf(
                crate::policy::rgpf::errors::rgpf_error::RgpfError::InvalidBool(2)
            ))
        ));
    }

    fn create_test_dir() -> PathBuf {
        let id = NEXT_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);
        
        let path = std::env::temp_dir().join(format!("rg-revision-store-tests-{id}"));

        let _ = std::fs::remove_dir_all(&path);
        
        std::fs::create_dir_all(&path).unwrap();

        path
    }
}
