use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::policy::compiler;
use crate::control_plane::types::ipc_status::IpcStatus;
use crate::control_plane::types::firewall_mode::FirewallMode;
use crate::control_plane::firewall_communication::sync::listener;
use crate::control_plane::errors::revision_store_error::RevisionStoreError;
use crate::control_plane::firewall_communication::publish::async_publisher;
use crate::control_plane::firewall_communication::config::FirewallIpcConfig;
use crate::control_plane::firewall_communication::runtime::revision_store::RevisionStore;
use crate::control_plane::firewall_communication::publish::event_ring::{EventRingHandle, channel};

use crate::control_plane::firewall_communication::runtime::state::{
    ActiveRevision, FirewallState, FirewallRuntimeState
};

/// Handle do obserwacji stanu i polityki firewalla.
#[derive(Clone)]
pub struct FirewallIpcHandle {
    state_rx: watch::Receiver<Arc<FirewallRuntimeState>>,
    event_ring: EventRingHandle
}

impl FirewallIpcHandle {
    pub fn state(&self) -> watch::Receiver<Arc<FirewallRuntimeState>> {
        self.state_rx.clone()
    }

    pub fn event_ring(&self) -> EventRingHandle {
        self.event_ring.clone()
    }
}

/// Główny runtime firewall-side IPC.
pub struct FirewallIpcRuntime {
    handle: FirewallIpcHandle,
    shutdown: CancellationToken,
    joins: Vec<JoinHandle<()>>,
}

impl FirewallIpcRuntime {
    /// Uruchamia nowy runtime IPC firewalla.
    pub async fn start(config: FirewallIpcConfig, block_icmp: bool) 
        -> Result<Self, Box<dyn std::error::Error + Send + Sync>> 
    {
        let initial_state =
            build_initial_runtime_state(&config.config_store_path, block_icmp).await?;

        let (state_tx, state_rx) =
            watch::channel(initial_state);
        
        let (event_ring, event_rx) = channel(config.event_queue_capacity);

        let state = FirewallState::new(
            RevisionStore::new(config.config_store_path.clone()),
            state_tx,
        );

        let shutdown = CancellationToken::new();

        let sync_join = tokio::spawn({
            let state = state.clone();
            
            let shutdown = shutdown.clone();
            
            let socket_path = config.sync_socket_path.clone();
            
            async move {
                if let Err(err) = listener::run(socket_path, state, shutdown).await {
                    tracing::error!(error = %err, "Sync IPC listener stopped with error");
                }
            }
        });

        let async_join = tokio::spawn({
            let state = state.clone();
            
            let shutdown = shutdown.clone();
            
            let config = config.clone();
            let event_rx = event_rx;
            
            async move {
                async_publisher::run(config, state, event_rx, shutdown).await;
            }
        });

        Ok(Self {
            handle: FirewallIpcHandle {
                state_rx,
                event_ring,
            },
            shutdown,
            joins: vec![sync_join, async_join],
        })
    }

    pub fn handle(&self) -> FirewallIpcHandle {
        self.handle.clone()
    }

    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.shutdown.cancel();
        
        for join in self.joins {
            let _ = join.await;
        }
        
        Ok(())
    }
}

async fn build_initial_runtime_state(
    config_store_path: &str,
    block_icmp: bool,
) -> Result<Arc<FirewallRuntimeState>, Box<dyn std::error::Error + Send + Sync>> {
    let fallback_policy = Arc::new(compiler::compile_fallback(block_icmp)?);

    let fallback_revision = Arc::new(ActiveRevision::fallback(fallback_policy));

    let revision_store = RevisionStore::new(config_store_path.to_string());

    match revision_store.load_current_active_revision().await {
        Ok(active_revision) => Ok(Arc::new(FirewallRuntimeState {
            mode: FirewallMode::Normal,
            active_revision,
            last_error_code: 0,
        })),
        Err(err) => {
            let code = u32::from(map_revision_store_error(&err));

            tracing::warn!(
                error = %err,
                config_store_path = config_store_path,
                "Failed to load active policy.bin during startup, falling back to compiled defaults"
            );

            Ok(Arc::new(FirewallRuntimeState {
                mode: FirewallMode::Degraded,
                active_revision: fallback_revision,
                last_error_code: code,
            }))
        }
    }
}

fn map_revision_store_error(err: &RevisionStoreError) -> IpcStatus {
    match err {
        RevisionStoreError::RevisionMismatch { .. } => IpcStatus::ErrPolicyRevisionMismatch,
        RevisionStoreError::ReadActiveLink(_)
        | RevisionStoreError::InvalidActiveTarget { .. }
        | RevisionStoreError::InvalidRevisionDirectory { .. }
        | RevisionStoreError::ReadPolicy(_)
        | RevisionStoreError::ParseRgpf(_) => IpcStatus::ErrPolicyLoadFailed,
    }
}

#[cfg(test)]
mod runtime_tests {
    use tokio::fs;
    use std::mem::size_of;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::build_initial_runtime_state;

    use crate::control_plane::types::ipc_status::IpcStatus;
    use crate::policy::rgpf::sections::rgpf_header::RgpfHeader;
    use crate::control_plane::types::firewall_mode::FirewallMode;
    use crate::policy::rgpf::sections::section_table::SectionEntry;
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

    #[tokio::test]
    async fn startup_uses_active_revision_from_store_when_available() {
        let root = create_test_dir();

        let versions_dir = root.join("versions");

        let revision_dir = versions_dir.join("320");

        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();

        fs::write(revision_dir.join("policy.bin"), build_policy_bin(320)).await.unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let state = build_initial_runtime_state(root.to_str().unwrap(), false).await.unwrap();

        assert_eq!(state.mode, FirewallMode::Normal);
        assert_eq!(state.last_error_code, 0);
        assert_eq!(state.active_revision.revision_id(), 320);
        assert_eq!(state.active_revision.policy_hash(), 0xABCD_EF12_3456_7890);
    }

    #[tokio::test]
    async fn startup_falls_back_and_sets_degraded_when_active_revision_is_missing() {
        let root = create_test_dir();

        let state = build_initial_runtime_state(root.to_str().unwrap(), false)
            .await.unwrap();

        assert_eq!(state.mode, FirewallMode::Degraded);
        assert_eq!(state.last_error_code, u32::from(IpcStatus::ErrPolicyLoadFailed));
        assert_eq!(state.active_revision.policy_hash(), 0);
    }

    #[tokio::test]
    async fn startup_uses_revision_mismatch_code_when_header_revision_differs_from_active_target() {
        let root = create_test_dir();

        let versions_dir = root.join("versions");

        let revision_dir = versions_dir.join("320");

        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();

        fs::write(revision_dir.join("policy.bin"), build_policy_bin(321)).await.unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let state = build_initial_runtime_state(root.to_str().unwrap(), false)
            .await.unwrap();

        assert_eq!(state.mode, FirewallMode::Degraded);
        assert_eq!(state.last_error_code, u32::from(IpcStatus::ErrPolicyRevisionMismatch));
        assert_eq!(state.active_revision.revision_id(), 0);
        assert_eq!(state.active_revision.policy_hash(), 0);
    }

    fn create_test_dir() -> PathBuf {
        let id = NEXT_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);

        let path = std::env::temp_dir().join(format!("rg-runtime-tests-{id}"));

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
