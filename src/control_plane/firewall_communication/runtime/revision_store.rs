use std::sync::Arc;
use tracing::{debug, info, trace, warn};
use std::path::{Component, Path, PathBuf};

use crate::policy::rgpf::sections::rgpf_file::RgpfFile;
use crate::control_plane::logging::payload_preview_hex;
use crate::policy::rgpf::load::compiled_policy::load_compiled_policy;
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
    pub async fn load_current_active_revision(&self) -> Result<Arc<ActiveRevision>, RevisionStoreError> {
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
        
        let compiled_policy = Arc::new(load_compiled_policy(&file)?);
        
        let rule_count = compiled_policy.metadata().rule_count;

        info!(
            revision_id = actual_revision_id,
            policy_hash,
            rule_count,
            policy_path = %policy_path.display(),
            "Loaded active policy revision from config store"
        );

        Ok(Arc::new(ActiveRevision::from_rgpf(
            bytes,
            compiled_policy,
            actual_revision_id,
            policy_hash,
            rule_count,
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
    use std::mem::size_of;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{parse_active_revision_target, RevisionStore};

    use crate::policy::rgpf::sections::rgpf_header::RgpfHeader;
    use crate::policy::rgpf::sections::section_table::SectionEntry;
    use crate::control_plane::errors::revision_store_error::RevisionStoreError;
    use crate::policy::rgpf::sections::rule_tree::entries::{RuleEntry, RuleNode, RuleTreeSectionHeader};
    
    use crate::policy::rgpf::constants::{
        NO_INDEX,
        VERDICT_DROP,
        NODE_KIND_MATCH,
        NODE_KIND_VERDICT,
        VERDICT_ALLOW_WARN,
        SECTION_STRING_TABLE,
        PATTERN_KIND_WILDCARD,
        SECTION_DEFAULT_VERDICT,
        SECTION_RULE_TREE_TABLE,
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
        fs::write(revision_dir.join("policy.bin"), build_policy_bin(320)).await.unwrap();
        
        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let store = RevisionStore::new(&root);

        let revision = store.load_active_revision(320).await.unwrap();

        assert_eq!(revision.revision_id(), 320);
        assert_eq!(revision.policy_hash(), 0xABCD_EF12_3456_7890);
        assert_eq!(revision.rule_count(), 1);
        assert!(revision.rgpf().unwrap().is_some());
    }

    #[tokio::test]
    async fn load_current_active_revision_reads_revision_from_target() {
        let root = create_test_dir();
        
        let versions_dir = root.join("versions");
        
        let revision_dir = versions_dir.join("320");
        
        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();
        
        fs::write(revision_dir.join("policy.bin"), build_policy_bin(320)).await.unwrap();
        
        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let store = RevisionStore::new(&root);

        let revision = store.load_current_active_revision().await.unwrap();

        assert_eq!(revision.revision_id(), 320);
        assert_eq!(revision.policy_hash(), 0xABCD_EF12_3456_7890);
    }

    #[tokio::test]
    async fn load_active_revision_rejects_target_revision_mismatch() {
        let root = create_test_dir();
        
        let versions_dir = root.join("versions");
        
        let revision_dir = versions_dir.join("320");
        
        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();
        
        fs::write(revision_dir.join("policy.bin"), build_policy_bin(320)).await.unwrap();
        
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
        
        fs::write(current_dir.join("policy.bin"), build_policy_bin(320)).await.unwrap();
        
        #[cfg(unix)]
        std::os::unix::fs::symlink("current/320", &active_link).unwrap();

        let store = RevisionStore::new(&root);

        let result = store.load_active_revision(320).await;

        assert!(matches!(result, Err(RevisionStoreError::InvalidActiveTarget { .. })));
    }

    fn create_test_dir() -> PathBuf {
        let id = NEXT_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);
        
        let path = std::env::temp_dir().join(format!("rg-revision-store-tests-{id}"));

        let _ = std::fs::remove_dir_all(&path);
        
        std::fs::create_dir_all(&path).unwrap();

        path
    }

    //noinspection DuplicatedCode
    fn build_policy_bin(revision_id: u64) -> Vec<u8> {
        let strings = build_string_table(&["default", "Loaded from RGPF", "allow-from-rgpf"]);

        let name_off = 0u32;
        let desc_off = string_entry_offset("default");
        let msg_off = desc_off + string_entry_len("Loaded from RGPF") as u32;

        let rule_tree = build_rule_tree_section(name_off, desc_off, msg_off);
        let default_verdict = build_default_verdict_section();

        let header_len = size_of::<RgpfHeader>();
        let section_count = 3u16;
        let section_table_len = size_of::<SectionEntry>() * usize::from(section_count);

        let mut cursor = header_len + section_table_len;

        let string_offset = cursor;
        cursor += strings.len();

        let rule_tree_offset = cursor;
        cursor += rule_tree.len();

        let default_offset = cursor;
        cursor += default_verdict.len();

        let mut bytes = Vec::with_capacity(cursor);
        bytes.resize(header_len, 0);

        let sections = [
            section_entry(SECTION_STRING_TABLE, string_offset, strings.len(), 3),
            section_entry(SECTION_RULE_TREE_TABLE, rule_tree_offset, rule_tree.len(), 1),
            section_entry(SECTION_DEFAULT_VERDICT, default_offset, default_verdict.len(), 1),
        ];

        for section in sections {
            bytes.extend_from_slice(&section);
        }

        bytes.extend_from_slice(&strings);
        bytes.extend_from_slice(&rule_tree);
        bytes.extend_from_slice(&default_verdict);

        let total_len = bytes.len() as u64;

        write_header(
            &mut bytes[..header_len],
            revision_id,
            0xABCD_EF12_3456_7890,
            section_count,
            header_len as u16,
            header_len as u64,
            total_len,
        );

        let crc = crc32c_with_zeroed_field(&bytes, file_crc32c_offset());
        let crc_offset = file_crc32c_offset();
        
        bytes[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());

        bytes
    }

    fn build_string_table(values: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();

        for value in values {
            bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }

        bytes
    }

    //noinspection DuplicatedCode
    fn build_rule_tree_section(name_off: u32, desc_off: u32, msg_off: u32) -> Vec<u8> {
        let header_len = size_of::<RuleTreeSectionHeader>();
        let rules_offset = header_len as u64;
        let nodes_offset = rules_offset + size_of::<RuleEntry>() as u64;
        let object_arena_offset = nodes_offset + (2 * size_of::<RuleNode>()) as u64;

        let mut arena = Vec::new();
        arena.extend_from_slice(&0u32.to_le_bytes());

        let wildcard_off = arena.len() as u32;
        arena.push(PATTERN_KIND_WILDCARD);
        arena.push(0);
        arena.extend_from_slice(&0u16.to_le_bytes());

        let allow_verdict_off = arena.len() as u32;
        arena.push(VERDICT_ALLOW_WARN);
        arena.push(0);
        arena.extend_from_slice(&0u16.to_le_bytes());
        arena.extend_from_slice(&msg_off.to_le_bytes());

        let mut bytes = Vec::new();

        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&rules_offset.to_le_bytes());
        bytes.extend_from_slice(&nodes_offset.to_le_bytes());
        bytes.extend_from_slice(&object_arena_offset.to_le_bytes());
        bytes.extend_from_slice(&(arena.len() as u64).to_le_bytes());

        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&name_off.to_le_bytes());
        bytes.extend_from_slice(&desc_off.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        bytes.push(NODE_KIND_MATCH);
        bytes.push(crate::policy::rgpf::constants::MATCH_KIND_PROTOCOL);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&wildcard_off.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&NO_INDEX.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        bytes.push(NODE_KIND_VERDICT);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&NO_INDEX.to_le_bytes());
        bytes.extend_from_slice(&NO_INDEX.to_le_bytes());
        bytes.extend_from_slice(&allow_verdict_off.to_le_bytes());

        bytes.extend_from_slice(&arena);

        bytes
    }

    fn build_default_verdict_section() -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(VERDICT_DROP);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        bytes
    }

    fn string_entry_offset(value: &str) -> u32 {
        string_entry_len(value) as u32
    }

    fn string_entry_len(value: &str) -> usize {
        4 + value.len()
    }

    fn section_entry(kind: u16, offset: usize, length: usize, item_count: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(offset as u64).to_le_bytes());
        bytes.extend_from_slice(&(length as u64).to_le_bytes());
        bytes.extend_from_slice(&item_count.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes
    }

    //noinspection DuplicatedCode
    fn write_header(
        bytes: &mut [u8],
        revision_id: u64,
        policy_hash: u64,
        section_count: u16,
        header_len: u16,
        section_table_offset: u64,
        file_len: u64,
    ) {
        let mut cursor = 0usize;

        push_u32(bytes, &mut cursor, crate::policy::rgpf::constants::RGPF_MAGIC);
        push_u16(bytes, &mut cursor, crate::policy::rgpf::constants::RGPF_MAJOR);
        push_u16(bytes, &mut cursor, crate::policy::rgpf::constants::RGPF_MINOR);
        push_u16(bytes, &mut cursor, header_len);
        push_u16(bytes, &mut cursor, section_count);
        push_u32(bytes, &mut cursor, 0);
        push_u64(bytes, &mut cursor, revision_id);
        push_u64(bytes, &mut cursor, 1_700_000_000_000);
        push_u64(bytes, &mut cursor, policy_hash);
        push_u64(bytes, &mut cursor, section_table_offset);
        push_u64(bytes, &mut cursor, file_len);
        push_u32(bytes, &mut cursor, 0);
        push_u32(bytes, &mut cursor, 0);
    }

    fn push_u16(bytes: &mut [u8], cursor: &mut usize, value: u16) {
        bytes[*cursor..*cursor + 2].copy_from_slice(&value.to_le_bytes());
        *cursor += 2;
    }

    fn push_u32(bytes: &mut [u8], cursor: &mut usize, value: u32) {
        bytes[*cursor..*cursor + 4].copy_from_slice(&value.to_le_bytes());
        *cursor += 4;
    }

    fn push_u64(bytes: &mut [u8], cursor: &mut usize, value: u64) {
        bytes[*cursor..*cursor + 8].copy_from_slice(&value.to_le_bytes());
        *cursor += 8;
    }

    fn file_crc32c_offset() -> usize {
        56
    }

    fn crc32c_with_zeroed_field(bytes: &[u8], field_offset: usize) -> u32 {
        let prefix = &bytes[..field_offset];
        
        let suffix = &bytes[field_offset + 4..];

        let mut crc = crc32c_update(!0u32, prefix);
        
        crc = crc32c_update(crc, &[0, 0, 0, 0]);
        crc = crc32c_update(crc, suffix);

        !crc
    }

    fn crc32c_update(mut crc: u32, bytes: &[u8]) -> u32 {
        for &byte in bytes {
            crc ^= u32::from(byte);

            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0x82F63B78 & mask);
            }
        }

        crc
    }
}
