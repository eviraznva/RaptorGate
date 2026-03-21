use std::path::Path;

use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

use crate::control_plane::firewall_communication::sync::session;
use crate::control_plane::firewall_communication::runtime::state::FirewallState;

/// Nasłuchuje na synchronicznym sockecie IPC i obsługuje kolejne połączenia.
pub async fn run(socket_path: String, state: FirewallState, shutdown: CancellationToken, ) 
    -> std::io::Result<()> 
{
    prepare_socket_path(&socket_path).await?;
    
    let listener = UnixListener::bind(&socket_path)?;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                cleanup_socket_path(&socket_path).await.ok();
                
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                
                tokio::spawn({
                    let state = state.clone();
                    
                    let shutdown = shutdown.clone();
                    
                    async move {
                        if let Err(err) = session::run(stream, state, shutdown).await {
                            tracing::warn!(error = %err, "IPC sync session failed");
                        }
                    }
                });
            }
        }
    }
}

async fn prepare_socket_path(socket_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(socket_path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    if Path::new(socket_path).exists() {
        let _ = tokio::fs::remove_file(socket_path).await;
    }

    Ok(())
}

async fn cleanup_socket_path(socket_path: &str) -> std::io::Result<()> {
    if Path::new(socket_path).exists() {
        tokio::fs::remove_file(socket_path).await?;
    }
    
    Ok(())
}

#[cfg(test)]
mod listener_tests {
    use std::mem::size_of;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::fs;
    use tokio::net::UnixStream;
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;

    use crate::policy::compiler;
    use crate::policy::rgpf::constants::{
        NO_INDEX,
        NODE_KIND_MATCH,
        NODE_KIND_VERDICT,
        PATTERN_KIND_WILDCARD,
        SECTION_DEFAULT_VERDICT,
        SECTION_RULE_TREE_TABLE,
        SECTION_STRING_TABLE,
        VERDICT_ALLOW_WARN,
        VERDICT_DROP,
    };
    use crate::policy::rgpf::sections::rgpf_header::RgpfHeader;
    use crate::policy::rgpf::sections::section_table::SectionEntry;
    use crate::control_plane::types::ipc_status::IpcStatus;
    use crate::control_plane::types::firewall_mode::FirewallMode;
    use crate::control_plane::ipc::sync_endpoint::SyncIpcEndpoint;
    use crate::control_plane::errors::sync_ipc_endpoint_error::SyncIpcEndpointError;
    use crate::control_plane::messages::requests::get_status_request::GetStatusRequest;
    use crate::control_plane::messages::responses::get_status_response::GetStatusResponse;
    use crate::control_plane::messages::requests::activate_revision_request::ActivateRevisionRequest;
    use crate::control_plane::messages::responses::activate_revision_response::ActivateRevisionResponse;
    use crate::control_plane::firewall_communication::runtime::revision_store::RevisionStore;
    use crate::control_plane::firewall_communication::runtime::state::{
        ActiveRevision, FirewallRuntimeState, FirewallState
    };

    static NEXT_TEST_DIR_ID: AtomicU64 = AtomicU64::new(1);

    #[tokio::test]
    #[ignore = "requires Unix IPC transport support from the execution environment"]
    async fn activate_revision_over_real_socket_updates_runtime_state() {
        let root = create_test_dir();
        
        let versions_dir = root.join("versions");
        let revision_dir = versions_dir.join("320");
        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();
        fs::write(revision_dir.join("policy.bin"), build_policy_bin(320)).await.unwrap();
        
        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let state = build_state(root.to_str().unwrap(), FirewallMode::Normal, 0);
        
        let shutdown = CancellationToken::new();
        
        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        
        let session_join = tokio::spawn({
            let state = state.clone();
            
            let shutdown = shutdown.clone();
            
            async move {
                super::super::session::run(server_stream, state, shutdown).await.unwrap();
            }
        });

        let mut client = SyncIpcEndpoint::from_stream(client_stream);

        let response: ActivateRevisionResponse = client.send(&ActivateRevisionRequest { revision_id: 320 })
            .await.unwrap();

        assert_eq!(response.loaded_revision_id, 320);
        assert_eq!(response.policy_hash, 0xABCD_EF12_3456_7890);
        assert_eq!(response.rule_count, 1);

        let status: GetStatusResponse = client.send(&GetStatusRequest).await.unwrap();

        assert_eq!(status.mode, FirewallMode::Normal);
        assert_eq!(status.loaded_revision_id, 320);
        assert_eq!(status.policy_hash, 0xABCD_EF12_3456_7890);
        assert_eq!(status.last_error_code, 0);

        let snapshot = state.snapshot();

        assert_eq!(snapshot.mode, FirewallMode::Normal);
        assert_eq!(snapshot.active_revision.revision_id(), 320);
        assert_eq!(snapshot.active_revision.policy_hash(), 0xABCD_EF12_3456_7890);

        shutdown.cancel();
        
        session_join.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Unix IPC transport support from the execution environment"]
    async fn activate_revision_failure_over_real_socket_keeps_previous_revision_and_sets_degraded_mode() {
        let root = create_test_dir();
        
        let versions_dir = root.join("versions");
        
        let revision_dir = versions_dir.join("321");
        
        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();
        
        fs::write(revision_dir.join("policy.bin"), build_policy_bin(321)).await.unwrap();
        
        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/321", &active_link).unwrap();

        let state = build_state(root.to_str().unwrap(), FirewallMode::Normal, 0);
        
        let shutdown = CancellationToken::new();
        
        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        
        let session_join = tokio::spawn({
            let state = state.clone();
            
            let shutdown = shutdown.clone();
            async move {
                super::session::run(server_stream, state, shutdown).await.unwrap();
            }
        });

        let mut client = SyncIpcEndpoint::from_stream(client_stream);

        let err = client
            .send::<ActivateRevisionRequest, ActivateRevisionResponse>(&ActivateRevisionRequest { revision_id: 320 })
            .await.unwrap_err();

        match err {
            SyncIpcEndpointError::RemoteError { status, .. } => {
                assert_eq!(status, IpcStatus::ErrPolicyRevisionMismatch);
            }
            other => panic!("unexpected sync endpoint error: {other:?}"),
        }

        let status: GetStatusResponse = client.send(&GetStatusRequest).await.unwrap();

        assert_eq!(status.mode, FirewallMode::Degraded);
        assert_eq!(status.loaded_revision_id, 0);
        assert_eq!(status.policy_hash, 0);
        assert_eq!(status.last_error_code, u32::from(IpcStatus::ErrPolicyRevisionMismatch));

        let snapshot = state.snapshot();

        assert_eq!(snapshot.mode, FirewallMode::Degraded);
        assert_eq!(snapshot.active_revision.revision_id(), 0);
        assert_eq!(snapshot.active_revision.policy_hash(), 0);

        shutdown.cancel();
        
        session_join.await.unwrap();
    }

    fn build_state(config_store_path: &str, mode: FirewallMode, last_error_code: u32) -> FirewallState {
        let policy = Arc::new(compiler::compile_fallback(false).unwrap());
        
        let active_revision = Arc::new(ActiveRevision::fallback(policy));
        
        let runtime_state = Arc::new(FirewallRuntimeState {
            mode,
            active_revision,
            last_error_code,
        });
        
        let (runtime_tx, _) = watch::channel(runtime_state);

        FirewallState::new(
            RevisionStore::new(config_store_path),
            runtime_tx,
        )
    }

    fn create_test_dir() -> PathBuf {
        let id = NEXT_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);
        
        let path = std::env::temp_dir().join(format!("rg-sync-listener-tests-{id}"));

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

    fn build_string_table(strings: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();

        for value in strings {
            let len = value.len() as u32;
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }

        bytes
    }

    fn build_rule_tree_section(name_off: u32, desc_off: u32, msg_off: u32) -> Vec<u8> {
        let header_len = size_of::<crate::policy::rgpf::sections::rule_tree::entries::RuleTreeSectionHeader>();
        
        let rules_offset = header_len as u64;
        
        let nodes_offset = rules_offset + size_of::<crate::policy::rgpf::sections::rule_tree::entries::RuleEntry>() as u64;
        
        let object_arena_offset = nodes_offset + (2 * size_of::<crate::policy::rgpf::sections::rule_tree::entries::RuleNode>()) as u64;

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

    fn string_entry_len(value: &str) -> usize {
        4 + value.len()
    }

    fn string_entry_offset(target: &str) -> u32 {
        match target {
            "default" => 4 + "default".len() as u32,
            "Loaded from RGPF" => {
                let first = string_entry_len("default") as u32;
                first + 4
            }
            _ => panic!("unexpected string target: {target}"),
        }
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
