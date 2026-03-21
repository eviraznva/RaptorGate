use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

use crate::control_plane::types::ipc_status::IpcStatus;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
use crate::control_plane::errors::ipc_client_error::IpcClientError;
use crate::control_plane::messages::responses::ping_response::PingResponse;
use crate::control_plane::ipc::sync_endpoint::{RequestMeta, SyncIpcEndpoint};
use crate::control_plane::errors::sync_ipc_endpoint_error::SyncIpcEndpointError;
use crate::control_plane::firewall_communication::runtime::state::FirewallState;
use crate::control_plane::messages::responses::get_status_response::GetStatusResponse;
use crate::control_plane::messages::responses::activate_revision_response::ActivateRevisionResponse;
use crate::control_plane::messages::responses::get_network_interfaces_response::GetNetworkInterfacesResponse;

use crate::control_plane::firewall_communication::sync::dispatch::{
    dispatch_request, DispatchOutcome, ResponsePayload
};
use crate::control_plane::logging::payload_preview_hex;

/// Obsługuje jedno połączenie synchroniczne UDS.
#[tracing::instrument(skip(stream, state, shutdown))]
pub async fn run(stream: UnixStream, state: FirewallState, shutdown: CancellationToken) 
    -> std::io::Result<()> 
{
    let mut endpoint = SyncIpcEndpoint::from_stream(stream);

    tracing::debug!("Started sync IPC session");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("Stopping sync IPC session due to shutdown");
                return Ok(());
            },
            
            frame = endpoint.receive_frame() => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(err) if is_clean_disconnect(&err) => {
                        tracing::debug!("Sync IPC session closed by peer");
                        return Ok(());
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "IPC sync session terminated by read error");
                        return Ok(());
                    }
                };

                tracing::debug!(
                    kind = ?frame.kind(),
                    opcode = ?frame.opcode(),
                    status = ?frame.status(),
                    request_id = frame.request_id(),
                    sequence_no = frame.sequence_no(),
                    payload_len = frame.payload_length(),
                    "Received sync IPC frame"
                );
                
                tracing::trace!(
                    kind = ?frame.kind(),
                    opcode = ?frame.opcode(),
                    status = ?frame.status(),
                    request_id = frame.request_id(),
                    sequence_no = frame.sequence_no(),
                    payload_len = frame.payload_length(),
                    payload_preview_hex = %payload_preview_hex(frame.payload(), 32),
                    "Received sync IPC frame details"
                );

                if frame.kind() != IpcFrameKind::Request {
                    tracing::warn!(kind = ?frame.kind(), "Ignoring non-request frame on sync channel");
                    
                    continue;
                }

                if frame.request_id() == 0 {
                    tracing::warn!("Ignoring request frame with request_id = 0");
                    
                    continue;
                }

                if frame.status() != IpcStatus::Ok {
                    let meta = RequestMeta::from_frame(&frame);

                    tracing::warn!(
                        opcode = ?frame.opcode(),
                        request_id = frame.request_id(),
                        sequence_no = frame.sequence_no(),
                        status = ?frame.status(),
                        "Rejecting sync IPC request with non-success status"
                    );
                    
                    endpoint.send_error(&meta, IpcStatus::ErrBadFrame, bytes::Bytes::new()).await.ok();
                    
                    continue;
                }

                let meta = RequestMeta::from_frame(&frame);
                
                match dispatch_request(&state, meta, &frame).await {
                    DispatchOutcome::Success { meta, payload } => {
                        tracing::debug!(
                            opcode = ?meta.opcode,
                            request_id = meta.request_id,
                            sequence_no = meta.sequence_no,
                            "Sync IPC request dispatched successfully"
                        );
                        
                        match payload {
                            ResponsePayload::Ping(response) => {
                                let _ = endpoint.send_response::<PingResponse>(&meta, &response).await;
                            }
                            ResponsePayload::Status(response) => {
                                let _ = endpoint.send_response::<GetStatusResponse>(&meta, &response).await;
                            }
                            ResponsePayload::NetworkInterfaces(response) => {
                                let _ = endpoint.send_response::<GetNetworkInterfacesResponse>(&meta, &response).await;
                            }
                            ResponsePayload::ActivateRevision(response) => {
                                let _ = endpoint.send_response::<ActivateRevisionResponse>(&meta, &response).await;
                            }
                        }
                    }
                    
                    DispatchOutcome::Error { meta, status, payload } => {
                        tracing::warn!(
                            opcode = ?meta.opcode,
                            request_id = meta.request_id,
                            sequence_no = meta.sequence_no,
                            status = ?status,
                            payload_len = payload.len(),
                            payload_preview_hex = %payload_preview_hex(&payload, 32),
                            "Dispatch returned sync IPC error response"
                        );
                        
                        let _ = endpoint.send_error(&meta, status, payload).await;
                    }
                }
            }
        }
    }
}

fn is_clean_disconnect(err: &SyncIpcEndpointError) -> bool {
    matches!(
        err,
        SyncIpcEndpointError::Transport(IpcClientError::EndOfStream { field: "magic" })
    )
}
