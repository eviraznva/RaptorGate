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

                                        state.set_last_error_code(200);

                                        break;
                                    } else {
                                        state.set_last_error_code(0);
                                    }
                                }
                                None => return,
                            }
                        }

                        _ = tokio::time::sleep(config.heartbeat_interval) => {
                            let event: HeartbeatEvent = state.build_heartbeat_event().await;

                            if let Err(err) = endpoint.send_event(&event, IpcFrameFlags::NONE).await {
                                tracing::warn!(error = %err, "Async IPC heartbeat send failed; reconnecting");

                                state.set_last_error_code(200);

                                break;
                            } else {
                                state.set_last_error_code(0);
                            }
                        }
                    }
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, socket = %config.async_socket_path, "Async IPC connect failed");

                state.set_last_error_code(200);

                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(config.async_reconnect_interval) => {}
                }
            }
        }
    }
}
