use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::control_plane::ipc::async_endpoint::AsyncIpcEndpoint;
use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
use crate::control_plane::messages::events::heartbeat_event::HeartbeatEvent;
use crate::control_plane::firewall_communication::config::FirewallIpcConfig;
use crate::control_plane::firewall_communication::runtime::state::FirewallState;
use crate::control_plane::firewall_communication::publish::event_ring::QueuedEvent;

/// Utrzymuje połączenie asynchroniczne i cyklicznie publikuje heartbeat.
#[tracing::instrument(skip(config, state, event_rx, shutdown), fields(
    socket = %config.async_socket_path,
    heartbeat_interval_ms = config.heartbeat_interval.as_millis()
))]
pub async fn run(
    config: FirewallIpcConfig,
    state: FirewallState,
    mut event_rx: mpsc::Receiver<QueuedEvent>,
    shutdown: CancellationToken,
) {
    info!(
        socket = %config.async_socket_path,
        heartbeat_interval_ms = config.heartbeat_interval.as_millis(),
        async_reconnect_interval_ms = config.async_reconnect_interval.as_millis(),
        "Starting async IPC publisher"
    );

    loop {
        if shutdown.is_cancelled() {
            info!("Stopping async IPC publisher because shutdown was requested");
            return;
        }

        match AsyncIpcEndpoint::connect(&config.async_socket_path).await {
            Ok(mut endpoint) => {
                info!(socket = %config.async_socket_path, "Connected async IPC publisher");

                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            info!("Stopping async IPC publisher session because shutdown was requested");
                            return;
                        },

                        event = event_rx.recv() => {
                            match event {
                                Some(event) => {
                                    trace!(
                                        opcode = ?event.opcode(),
                                        flags = event.flags().bits(),
                                        payload_len = event.payload().len(),
                                        "Dequeued event from event ring"
                                    );

                                    if let Err(err) = endpoint
                                        .send_encoded_event(event.opcode(), event.flags(), event.payload().clone())
                                        .await
                                    {
                                        warn!(
                                            error = %err,
                                            opcode = ?event.opcode(),
                                            payload_len = event.payload().len(),
                                            "Async IPC queued event send failed; reconnecting"
                                        );

                                        state.set_transient_error_code(200);

                                        break;
                                    } else {
                                        debug!(
                                            opcode = ?event.opcode(),
                                            payload_len = event.payload().len(),
                                            "Sent queued async IPC event"
                                        );
                                        state.set_transient_error_code(0);
                                    }
                                }
                                None => {
                                    info!("Stopping async IPC publisher because event ring receiver was closed");
                                    return;
                                }
                            }
                        }

                        _ = tokio::time::sleep(config.heartbeat_interval) => {
                            let event: HeartbeatEvent = state.build_heartbeat_event().await;

                            if let Err(err) = endpoint.send_event(&event, IpcFrameFlags::NONE).await {
                                warn!(
                                    error = %err,
                                    revision_id = event.loaded_revision_id,
                                    mode = ?event.mode,
                                    "Async IPC heartbeat send failed; reconnecting"
                                );

                                state.set_transient_error_code(200);

                                break;
                            } else {
                                debug!(
                                    revision_id = event.loaded_revision_id,
                                    policy_hash = event.policy_hash,
                                    mode = ?event.mode,
                                    uptime_sec = event.uptime_sec,
                                    "Sent async IPC heartbeat event"
                                );
                                state.set_transient_error_code(0);
                            }
                        }
                    }
                }
            }
            Err(err) => {
                warn!(error = %err, socket = %config.async_socket_path, "Async IPC connect failed");

                state.set_transient_error_code(200);

                debug!(
                    socket = %config.async_socket_path,
                    reconnect_after_ms = config.async_reconnect_interval.as_millis(),
                    "Scheduling async IPC reconnect"
                );

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
