use std::path::Path;

use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::control_plane::firewall_communication::sync::session;
use crate::control_plane::firewall_communication::runtime::state::FirewallState;

/// Nasłuchuje na synchronicznym sockecie IPC i obsługuje kolejne połączenia.
#[tracing::instrument(skip(state, shutdown), fields(socket = %socket_path))]
pub async fn run(socket_path: String, state: FirewallState, shutdown: CancellationToken, ) 
    -> std::io::Result<()> 
{
    info!(socket = %socket_path, "Preparing sync IPC listener socket");
    
    prepare_socket_path(&socket_path).await?;
    
    let listener = UnixListener::bind(&socket_path)?;

    info!(socket = %socket_path, "Sync IPC listener started");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!(socket = %socket_path, "Shutting down sync IPC listener");
                
                cleanup_socket_path(&socket_path).await.ok();
                
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, addr) = match accepted {
                    Ok(value) => value,
                    Err(err) => {
                        error!(socket = %socket_path, error = %err, "Failed to accept sync IPC connection");
                        return Err(err);
                    }
                };

                debug!(socket = %socket_path, peer = ?addr, "Accepted sync IPC session");
                
                tokio::spawn({
                    let state = state.clone();
                    
                    let shutdown = shutdown.clone();
                    
                    async move {
                        if let Err(err) = session::run(stream, state, shutdown).await {
                            warn!(error = %err, "IPC sync session failed");
                        }
                    }
                });
            }
        }
    }
}

async fn prepare_socket_path(socket_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(socket_path).parent() {
        trace!(socket = %socket_path, parent = %parent.display(), "Ensuring sync IPC socket parent directory exists");
        tokio::fs::create_dir_all(parent).await?;
    }

    if Path::new(socket_path).exists() {
        trace!(socket = %socket_path, "Removing stale sync IPC socket file");
        let _ = tokio::fs::remove_file(socket_path).await;
    }

    Ok(())
}

async fn cleanup_socket_path(socket_path: &str) -> std::io::Result<()> {
    if Path::new(socket_path).exists() {
        trace!(socket = %socket_path, "Cleaning up sync IPC socket file");
        tokio::fs::remove_file(socket_path).await?;
    }
    
    Ok(())
}

#[cfg(test)]
mod listener_tests {
    use std::sync::Arc;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::fs;
    use tokio::sync::watch;
    use tokio::net::UnixStream;
    use tokio_util::sync::CancellationToken;

    use crate::policy::compiler;
    use crate::control_plane::types::ipc_status::IpcStatus;
    use crate::control_plane::types::firewall_mode::FirewallMode;
    use crate::control_plane::ipc::sync_endpoint::SyncIpcEndpoint;
    use crate::control_plane::errors::sync_ipc_endpoint_error::SyncIpcEndpointError;
    use crate::control_plane::messages::requests::get_status_request::GetStatusRequest;
    use crate::control_plane::messages::responses::get_status_response::GetStatusResponse;
    use crate::control_plane::firewall_communication::runtime::revision_store::RevisionStore;
    use crate::policy::rgpf::test_helpers::{build_policy_bin, TEST_POLICY_HASH, TEST_POLICY_SOURCE};
    use crate::control_plane::messages::requests::activate_revision_request::ActivateRevisionRequest;
    use crate::control_plane::messages::responses::activate_revision_response::ActivateRevisionResponse;
    
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
        fs::write(revision_dir.join("policy.bin"), build_policy_bin(320, TEST_POLICY_SOURCE)).await.unwrap();
        
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
        assert_eq!(response.policy_hash, TEST_POLICY_HASH);
        assert_eq!(response.rule_count, 1);

        let status: GetStatusResponse = client.send(&GetStatusRequest).await.unwrap();

        assert_eq!(status.mode, FirewallMode::Normal);
        assert_eq!(status.loaded_revision_id, 320);
        assert_eq!(status.policy_hash, TEST_POLICY_HASH);
        assert_eq!(status.last_error_code, 0);

        let snapshot = state.snapshot();

        assert_eq!(snapshot.mode, FirewallMode::Normal);
        assert_eq!(snapshot.active_revision.revision_id(), 320);
        assert_eq!(snapshot.active_revision.policy_hash(), TEST_POLICY_HASH);

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
        
        fs::write(revision_dir.join("policy.bin"), build_policy_bin(321, TEST_POLICY_SOURCE)).await.unwrap();
        
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
}
