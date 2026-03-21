use bytes::Bytes;
use tracing::{debug, info, trace, warn};

use crate::control_plane::ipc::ipc_frame::IpcFrame;
use crate::control_plane::ipc::ipc_message::IpcMessage;
use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::types::ipc_status::IpcStatus;
use crate::control_plane::ipc::sync_endpoint::RequestMeta;
use crate::control_plane::messages::requests::ping_request::PingRequest;
use crate::control_plane::firewall_communication::misc::interface_probe;
use crate::control_plane::errors::revision_store_error::RevisionStoreError;
use crate::control_plane::messages::responses::ping_response::PingResponse;
use crate::control_plane::firewall_communication::runtime::state::FirewallState;
use crate::control_plane::messages::requests::get_status_request::GetStatusRequest;
use crate::control_plane::messages::responses::get_status_response::GetStatusResponse;
use crate::control_plane::messages::requests::activate_revision_request::ActivateRevisionRequest;
use crate::control_plane::messages::responses::activate_revision_response::ActivateRevisionResponse;
use crate::control_plane::messages::requests::get_network_interfaces_request::GetNetworkInterfacesRequest;
use crate::control_plane::messages::responses::get_network_interfaces_response::GetNetworkInterfacesResponse;

/// Wynik dispatchu pojedynczego requestu IPC.
#[derive(Debug)]
pub enum DispatchOutcome {
    Success {
        meta: RequestMeta,
        payload: ResponsePayload,
    },
    Error {
        meta: RequestMeta,
        status: IpcStatus,
        payload: Bytes,
    },
}

/// Typowany payload odpowiedzi sukcesu.
#[derive(Debug)]
pub enum ResponsePayload {
    Ping(PingResponse),
    Status(GetStatusResponse),
    NetworkInterfaces(GetNetworkInterfacesResponse),
    ActivateRevision(ActivateRevisionResponse),
}

/// Dispatchuje pojedynczą ramkę request-response po stronie firewalla.
#[tracing::instrument(skip(state, frame), fields(
    opcode = ?frame.opcode(),
    request_id = meta.request_id,
    sequence_no = meta.sequence_no
))]
pub async fn dispatch_request(state: &FirewallState, meta: RequestMeta, frame: &IpcFrame) 
    -> DispatchOutcome 
{
    debug!(
        opcode = ?frame.opcode(),
        request_id = meta.request_id,
        sequence_no = meta.sequence_no,
        payload_len = frame.payload_length(),
        "Dispatching sync IPC request"
    );

    match frame.opcode() {
        IpcOpcode::Ping => match PingRequest::decode_payload(frame.payload()) {
            Ok(request) => {
                trace!(
                    request_id = meta.request_id,
                    sequence_no = meta.sequence_no,
                    timestamp_ms = request.timestamp_ms,
                    "Decoded PING request payload"
                );

                DispatchOutcome::Success {
                    meta,
                    payload: ResponsePayload::Ping(PingResponse {
                        timestamp_ms: request.timestamp_ms,
                        peer_timestamp_ms: current_timestamp_ms(),
                    }),
                }
            }
            Err(err) => {
                warn!(
                    request_id = meta.request_id,
                    sequence_no = meta.sequence_no,
                    error = %err,
                    "Failed to decode PING request payload"
                );

                DispatchOutcome::Error {
                    meta,
                    status: IpcStatus::ErrMalformedPayload,
                    payload: Bytes::from(err.to_string()),
                }
            }
        },
        IpcOpcode::GetStatus => match GetStatusRequest::decode_payload(frame.payload()) {
            Ok(_) => {
                trace!(
                    request_id = meta.request_id,
                    sequence_no = meta.sequence_no,
                    "Decoded GET_STATUS request payload"
                );

                DispatchOutcome::Success {
                    meta,
                    payload: ResponsePayload::Status(state.build_status_response().await),
                }
            }
            Err(err) => {
                warn!(
                    request_id = meta.request_id,
                    sequence_no = meta.sequence_no,
                    error = %err,
                    "Failed to decode GET_STATUS request payload"
                );

                DispatchOutcome::Error {
                    meta,
                    status: IpcStatus::ErrMalformedPayload,
                    payload: Bytes::from(err.to_string()),
                }
            }
        },
        IpcOpcode::GetNetworkInterfaces => {
            match GetNetworkInterfacesRequest::decode_payload(frame.payload()) {
                Ok(_) => match interface_probe::collect_interfaces() {
                    Ok(interfaces) => {
                        debug!(
                            request_id = meta.request_id,
                            sequence_no = meta.sequence_no,
                            interface_count = interfaces.len(),
                            "Collected network interfaces for GET_NETWORK_INTERFACES"
                        );

                        DispatchOutcome::Success {
                            meta,
                            payload: ResponsePayload::NetworkInterfaces(GetNetworkInterfacesResponse {
                                interfaces,
                            }),
                        }
                    }
                    Err(err) => {
                        warn!(
                            request_id = meta.request_id,
                            sequence_no = meta.sequence_no,
                            error = %err,
                            "Failed to enumerate network interfaces"
                        );

                        DispatchOutcome::Error {
                            meta,
                            status: IpcStatus::ErrInterfaceEnumFailed,
                            payload: Bytes::from(err.to_string()),
                        }
                    }
                },
                Err(err) => {
                    warn!(
                        request_id = meta.request_id,
                        sequence_no = meta.sequence_no,
                        error = %err,
                        "Failed to decode GET_NETWORK_INTERFACES request payload"
                    );

                    DispatchOutcome::Error {
                        meta,
                        status: IpcStatus::ErrMalformedPayload,
                        payload: Bytes::from(err.to_string()),
                    }
                }
            }
        }
        IpcOpcode::ActivateRevision => {
            match ActivateRevisionRequest::decode_payload(frame.payload()) {
                Ok(request) => {
                    trace!(
                        request_id = meta.request_id,
                        sequence_no = meta.sequence_no,
                        revision_id = request.revision_id,
                        "Decoded ACTIVATE_REVISION request payload"
                    );

                    let active_revision = state.active_revision();

                    if active_revision.revision_id() == request.revision_id {
                        state.activate_revision(active_revision.clone());

                        info!(
                            revision_id = active_revision.revision_id(),
                            policy_hash = active_revision.policy_hash(),
                            policy_count = active_revision.policy_count(),
                            "ActivateRevision requested for already active revision"
                        );

                        DispatchOutcome::Success {
                            meta,
                            payload: ResponsePayload::ActivateRevision(ActivateRevisionResponse {
                                loaded_revision_id: active_revision.revision_id(),
                                policy_hash: active_revision.policy_hash(),
                                rule_count: active_revision.policy_count() as u32,
                            }),
                        }
                    } else {
                        match state.revision_store().load_active_revision(request.revision_id).await {
                            Ok(active_revision) => {
                                let response = ActivateRevisionResponse {
                                    loaded_revision_id: active_revision.revision_id(),
                                    policy_hash: active_revision.policy_hash(),
                                    rule_count: active_revision.policy_count() as u32,
                                };

                                state.activate_revision(active_revision);

                                info!(
                                    revision_id = response.loaded_revision_id,
                                    policy_hash = response.policy_hash,
                                    rule_count = response.rule_count,
                                    "Activated new firewall policy revision"
                                );

                                DispatchOutcome::Success {
                                    meta,
                                    payload: ResponsePayload::ActivateRevision(response),
                                }
                            }
                            Err(err) => {
                                let status = map_revision_store_error(&err);
                                let code = u32::from(status);

                                state.mark_policy_error(code);

                                warn!(
                                    revision_id = request.revision_id,
                                    status = ?status,
                                    error = %err,
                                    "Failed to activate firewall policy revision"
                                );

                                DispatchOutcome::Error {
                                    meta,
                                    status,
                                    payload: Bytes::from(err.to_string()),
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        request_id = meta.request_id,
                        sequence_no = meta.sequence_no,
                        error = %err,
                        "Failed to decode ACTIVATE_REVISION request payload"
                    );

                    DispatchOutcome::Error {
                        meta,
                        status: IpcStatus::ErrMalformedPayload,
                        payload: Bytes::from(err.to_string()),
                    }
                }
            }
        }
        _ => {
            warn!(
                opcode = ?frame.opcode(),
                request_id = meta.request_id,
                sequence_no = meta.sequence_no,
                "Received unsupported sync IPC opcode"
            );

            DispatchOutcome::Error {
                meta,
                status: IpcStatus::ErrUnsupportedOpcode,
                payload: Bytes::new(),
            }
        }
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
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
mod sync_dispatch_tests {
    use std::sync::Arc;
    use tokio::sync::watch;
    
    use crate::policy::compiler;
    use crate::control_plane::types::ipc_status::IpcStatus;
    use crate::control_plane::ipc::ipc_message::IpcMessage;
    use crate::control_plane::types::ipc_opcode::IpcOpcode;
    use crate::control_plane::ipc::sync_endpoint::RequestMeta;
    use crate::control_plane::types::firewall_mode::FirewallMode;
    use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
    use super::{DispatchOutcome, ResponsePayload, dispatch_request};
    use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
    use crate::control_plane::messages::requests::ping_request::PingRequest;
    use crate::control_plane::ipc::ipc_frame::{IpcFrame, RGIPC_MAGIC, RGIPC_VERSION};
    use crate::control_plane::messages::requests::get_status_request::GetStatusRequest;
    use crate::control_plane::firewall_communication::runtime::revision_store::RevisionStore;
    use crate::control_plane::messages::requests::activate_revision_request::ActivateRevisionRequest;
    
    use crate::control_plane::firewall_communication::runtime::state::{
        ActiveRevision, FirewallState, FirewallRuntimeState
    };

    fn test_state() -> FirewallState {
        let policy = Arc::new(compiler::compile_fallback(false).unwrap());
        
        let active_revision = Arc::new(ActiveRevision::fallback(policy.clone()));
        
        let runtime_state = Arc::new(FirewallRuntimeState {
            mode: FirewallMode::Normal,
            active_revision: active_revision.clone(),
            last_error_code: 0,
        });

        let (runtime_tx, _) = watch::channel(runtime_state.clone());
        
        FirewallState::new(
            RevisionStore::new("/tmp/rg-dispatch-tests"),
            runtime_tx,
        )
    }

    #[tokio::test]
    async fn dispatch_ping_returns_typed_response() {
        let state = test_state();
        
        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Request,
            IpcFrameFlags::NONE,
            IpcOpcode::Ping,
            IpcStatus::Ok,
            7,
            11,
            PingRequest { timestamp_ms: 123 }.encode_payload().unwrap(),
        ).unwrap();

        let outcome = 
            dispatch_request(&state, RequestMeta::from_frame(&frame), &frame).await;

        match outcome {
            DispatchOutcome::Success {
                payload: ResponsePayload::Ping(response),
                ..
            } => {
                assert_eq!(response.timestamp_ms, 123);
                assert!(response.peer_timestamp_ms > 0);
            }
            other => panic!("unexpected dispatch outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_get_status_returns_success() {
        let state = test_state();
        
        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Request,
            IpcFrameFlags::NONE,
            IpcOpcode::GetStatus,
            IpcStatus::Ok,
            5,
            9,
            GetStatusRequest.encode_payload().unwrap(),
        ).unwrap();

        let outcome = 
            dispatch_request(&state, RequestMeta::from_frame(&frame), &frame).await;

        match outcome {
            DispatchOutcome::Success {
                payload: ResponsePayload::Status(response),
                ..
            } => {
                assert_eq!(response.loaded_revision_id, 0);
                assert_eq!(response.policy_hash, 0);
                assert_eq!(response.last_error_code, 0);
            }
            other => panic!("unexpected dispatch outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_activate_revision_for_current_revision_clears_degraded_mode() {
        let state = test_state();

        state.mark_policy_error(u32::from(IpcStatus::ErrPolicyLoadFailed));

        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Request,
            IpcFrameFlags::NONE,
            IpcOpcode::ActivateRevision,
            IpcStatus::Ok,
            6,
            10,
            ActivateRevisionRequest { revision_id: 0 }.encode_payload().unwrap(),
        ).unwrap();

        let outcome =
            dispatch_request(&state, RequestMeta::from_frame(&frame), &frame).await;

        match outcome {
            DispatchOutcome::Success {
                payload: ResponsePayload::ActivateRevision(response),
                ..
            } => {
                assert_eq!(response.loaded_revision_id, 0);
                assert_eq!(response.policy_hash, 0);
            }
            other => panic!("unexpected dispatch outcome: {other:?}"),
        }

        let snapshot = state.snapshot();

        assert_eq!(snapshot.mode, FirewallMode::Normal);
        assert_eq!(snapshot.last_error_code, 0);
        assert_eq!(snapshot.active_revision.revision_id(), 0);
    }

    #[tokio::test]
    async fn dispatch_activate_revision_error_keeps_previous_revision_and_sets_degraded_mode() {
        let state = test_state();

        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Request,
            IpcFrameFlags::NONE,
            IpcOpcode::ActivateRevision,
            IpcStatus::Ok,
            8,
            12,
            ActivateRevisionRequest { revision_id: 320 }.encode_payload().unwrap(),
        ).unwrap();

        let outcome =
            dispatch_request(&state, RequestMeta::from_frame(&frame), &frame).await;

        match outcome {
            DispatchOutcome::Error { status, .. } => {
                assert_eq!(status, IpcStatus::ErrPolicyLoadFailed);
            }
            other => panic!("unexpected dispatch outcome: {other:?}"),
        }

        let snapshot = state.snapshot();

        assert_eq!(snapshot.mode, FirewallMode::Degraded);
        assert_eq!(snapshot.last_error_code, u32::from(IpcStatus::ErrPolicyLoadFailed));
        assert_eq!(snapshot.active_revision.revision_id(), 0);
    }
}
