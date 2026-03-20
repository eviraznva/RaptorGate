use bytes::Bytes;

use crate::control_plane::ipc::ipc_frame::IpcFrame;
use crate::control_plane::ipc::ipc_message::IpcMessage;
use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::types::ipc_status::IpcStatus;
use crate::control_plane::ipc::sync_endpoint::RequestMeta;
use crate::control_plane::messages::requests::ping_request::PingRequest;
use crate::control_plane::firewall_communication::misc::interface_probe;
use crate::control_plane::firewall_communication::runtime::state::FirewallState;
use crate::control_plane::messages::responses::ping_response::PingResponse;
use crate::control_plane::messages::requests::get_status_request::GetStatusRequest;
use crate::control_plane::messages::responses::get_status_response::GetStatusResponse;
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
}

/// Dispatchuje pojedynczą ramkę request-response po stronie firewalla.
pub async fn dispatch_request(state: &FirewallState, meta: RequestMeta, frame: &IpcFrame) 
    -> DispatchOutcome 
{
    match frame.opcode() {
        IpcOpcode::Ping => match PingRequest::decode_payload(frame.payload()) {
            Ok(request) => DispatchOutcome::Success {
                meta,
                payload: ResponsePayload::Ping(PingResponse {
                    timestamp_ms: request.timestamp_ms,
                    peer_timestamp_ms: current_timestamp_ms(),
                }),
            },
            Err(err) => DispatchOutcome::Error {
                meta,
                status: IpcStatus::ErrMalformedPayload,
                payload: Bytes::from(err.to_string()),
            },
        },
        IpcOpcode::GetStatus => match GetStatusRequest::decode_payload(frame.payload()) {
            Ok(_) => DispatchOutcome::Success {
                meta,
                payload: ResponsePayload::Status(state.build_status_response().await),
            },
            Err(err) => DispatchOutcome::Error {
                meta,
                status: IpcStatus::ErrMalformedPayload,
                payload: Bytes::from(err.to_string()),
            },
        },
        IpcOpcode::GetNetworkInterfaces => {
            match GetNetworkInterfacesRequest::decode_payload(frame.payload()) {
                Ok(_) => match interface_probe::collect_interfaces() {
                    Ok(interfaces) => DispatchOutcome::Success {
                        meta,
                        payload: ResponsePayload::NetworkInterfaces(GetNetworkInterfacesResponse {
                            interfaces,
                        }),
                    },
                    Err(err) => DispatchOutcome::Error {
                        meta,
                        status: IpcStatus::ErrInterfaceEnumFailed,
                        payload: Bytes::from(err.to_string()),
                    },
                },
                Err(err) => DispatchOutcome::Error {
                    meta,
                    status: IpcStatus::ErrMalformedPayload,
                    payload: Bytes::from(err.to_string()),
                },
            }
        }
        _ => DispatchOutcome::Error {
            meta,
            status: IpcStatus::ErrUnsupportedOpcode,
            payload: Bytes::new(),
        },
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
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
    use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
    use super::{DispatchOutcome, ResponsePayload, dispatch_request};
    use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
    use crate::control_plane::messages::requests::ping_request::PingRequest;
    use crate::control_plane::firewall_communication::runtime::state::FirewallState;
    use crate::control_plane::ipc::ipc_frame::{IpcFrame, RGIPC_MAGIC, RGIPC_VERSION};
    use crate::control_plane::messages::requests::get_status_request::GetStatusRequest;

    fn test_state() -> FirewallState {
        let policy = Arc::new(compiler::compile_fallback(false).unwrap());
        
        let (_, policy_rx) = watch::channel(policy);
        
        FirewallState::new(policy_rx)
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
}
