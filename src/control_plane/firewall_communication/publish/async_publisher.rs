use tokio_util::sync::CancellationToken;

use crate::control_plane::ipc::async_endpoint::AsyncIpcEndpoint;
use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
use crate::control_plane::messages::events::heartbeat_event::HeartbeatEvent;
use crate::control_plane::firewall_communication::config::FirewallIpcConfig;
use crate::control_plane::firewall_communication::runtime::state::FirewallState;

/// Utrzymuje połączenie asynchroniczne i cyklicznie publikuje heartbeat.
pub async fn run(config: FirewallIpcConfig, state: FirewallState, shutdown: CancellationToken) {
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
                        
                        _ = tokio::time::sleep(config.heartbeat_interval) => {
                            let event: HeartbeatEvent = state.build_heartbeat_event().await;
                            
                            if let Err(err) = endpoint.send_event(&event, IpcFrameFlags::NONE).await {
                                tracing::warn!(error = %err, "Async IPC heartbeat send failed; reconnecting");
                                state.update_status(|status| status.last_error_code = 200).await;
                                break;
                            } else {
                                state.update_status(|status| status.last_error_code = 0).await;
                            }
                        }
                    }
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, socket = %config.async_socket_path, "Async IPC connect failed");
                
                state.update_status(|status| status.last_error_code = 200).await;
                
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(config.async_reconnect_interval) => {}
                }
            }
        }
    }
}
