use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::control_plane::ipc::async_endpoint::AsyncIpcEndpoint;
use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
use crate::control_plane::messages::events::heartbeat_event::HeartbeatEvent;
use crate::control_plane::firewall_communication::config::FirewallIpcConfig;
use crate::control_plane::firewall_communication::runtime::state::FirewallState;
use crate::control_plane::firewall_communication::publish::event_ring::QueuedEvent;

/// Utrzymuje połączenie asynchroniczne i cyklicznie publikuje heartbeat.
pub async fn run(
    config: FirewallIpcConfig,
    state: FirewallState,
    mut event_rx: mpsc::Receiver<QueuedEvent>,
    shutdown: CancellationToken,
) {
    loop {
        if shutdown.is_cancelled() {
            return;
        }

        match AsyncIpcEndpoint::connect(&config.async_socket_path).await {
            Ok(mut endpoint) => {
                tracing::info!(socket = %config.async_socket_path, "Connected async IPC publisher");

                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,

                        event = event_rx.recv() => {
                            match event {
                                Some(event) => {
                                    if let Err(err) = endpoint
                                        .send_encoded_event(event.opcode(), event.flags(), event.payload().clone())
                                        .await
                                    {
                                        tracing::warn!(error = %err, "Async IPC queued event send failed; reconnecting");

                                        state.set_transient_error_code(200);

                                        break;
                                    } else {
                                        state.set_transient_error_code(0);
                                    }
                                }
                                None => return,
                            }
                        }

                        _ = tokio::time::sleep(config.heartbeat_interval) => {
                            let event: HeartbeatEvent = state.build_heartbeat_event().await;

                            if let Err(err) = endpoint.send_event(&event, IpcFrameFlags::NONE).await {
                                tracing::warn!(error = %err, "Async IPC heartbeat send failed; reconnecting");

                                state.set_transient_error_code(200);

                                break;
                            } else {
                                state.set_transient_error_code(0);
                            }
                        }
                    }
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, socket = %config.async_socket_path, "Async IPC connect failed");

                state.set_transient_error_code(200);

                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(config.async_reconnect_interval) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod async_publisher_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::{mpsc, watch};
    use tokio_util::sync::CancellationToken;

    use crate::policy::compiler;
    use crate::control_plane::types::firewall_mode::FirewallMode;
    use crate::control_plane::firewall_communication::config::FirewallIpcConfig;
    use crate::control_plane::firewall_communication::runtime::revision_store::RevisionStore;
    
    use crate::control_plane::firewall_communication::runtime::state::{
        ActiveRevision, FirewallRuntimeState, FirewallState
    };

    use super::run;

    fn build_state(mode: FirewallMode, last_error_code: u32) -> FirewallState {
        let policy = Arc::new(compiler::compile_fallback(false).unwrap());
        
        let active_revision = Arc::new(ActiveRevision::fallback(policy));
        
        let runtime_state = Arc::new(FirewallRuntimeState {
            mode,
            active_revision,
            last_error_code,
        });
        
        let (runtime_tx, _) = watch::channel(runtime_state);

        FirewallState::new(
            RevisionStore::new("/tmp/rg-async-publisher-tests"),
            runtime_tx,
        )
    }

    #[tokio::test]
    async fn connect_failures_do_not_switch_runtime_into_degraded_mode() {
        let state = build_state(FirewallMode::Normal, 0);
        
        let (_event_tx, event_rx) = mpsc::channel(1);
        
        let shutdown = CancellationToken::new();
        
        let socket_path = std::env::temp_dir()
            .join("rg-async-publisher-missing.sock")
            .display()
            .to_string();

        let join = tokio::spawn(run(
            FirewallIpcConfig {
                sync_socket_path: String::new(),
                async_socket_path: socket_path,
                config_store_path: String::new(),
                heartbeat_interval: Duration::from_secs(60),
                async_reconnect_interval: Duration::from_millis(10),
                event_queue_capacity: 1,
            },
            state.clone(),
            event_rx,
            shutdown.clone(),
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let snapshot = state.snapshot();

                if snapshot.last_error_code == 200 {
                    assert_eq!(snapshot.mode, FirewallMode::Normal);
                    break;
                }

                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();

        shutdown.cancel();
        join.await.unwrap();
    }
}
