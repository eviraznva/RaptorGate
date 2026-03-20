use bytes::Bytes;
use tokio::net::UnixStream;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::control_plane::ipc::ipc_client::IpcClient;
use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::types::ipc_status::IpcStatus;
use crate::control_plane::ipc::ipc_counters::IpcCounters;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
use crate::control_plane::errors::sync_ipc_endpoint_error::SyncIpcEndpointError;
use crate::control_plane::ipc::ipc_frame::{IpcFrame, RGIPC_MAGIC, RGIPC_VERSION};
use crate::control_plane::ipc::ipc_message::{IpcRequestMessage, IpcResponseMessage};

/// Metadane odebranego żądania, potrzebne do zbudowania odpowiedzi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestMeta {
    pub magic: u32,
    pub version: u32,
    pub opcode: IpcOpcode,
    pub request_id: u64,
    pub sequence_no: u64,
}

/// Typowane żądanie odebrane z kanału synchronicznego.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRequest<Req> {
    pub meta: RequestMeta,
    pub message: Req,
}

/// Dwukierunkowy endpoint request-response dla kanału synchronicznego.
pub struct SyncIpcEndpoint<S = UnixStream> {
    client: IpcClient<S>,
    counters: IpcCounters,
}

impl SyncIpcEndpoint<UnixStream> {
    /// Otwiera połączenie z kanałem synchronicznym IPC.
    pub async fn connect(socket_path: &str) -> Result<Self, SyncIpcEndpointError> {
        let client = IpcClient::connect(socket_path).await?;

        Ok(Self {
            client,
            counters: IpcCounters::default(),
        })
    }
}

impl<S> SyncIpcEndpoint<S> where S: AsyncRead + AsyncWrite + Unpin {
    /// Tworzy endpoint z już przygotowanego strumienia.
    pub(crate) fn from_stream(stream: S) -> Self {
        Self {
            client: IpcClient::from_stream(stream),
            counters: IpcCounters::default(),
        }
    }

    /// Wysyła typowane żądanie i oczekuje typowanej odpowiedzi.
    pub async fn send<Req, Resp>(&mut self, request: &Req) -> Result<Resp, SyncIpcEndpointError> where
        Req: IpcRequestMessage,
        Resp: IpcResponseMessage 
    {
        if Req::OPCODE != Resp::OPCODE {
            return Err(SyncIpcEndpointError::MessageDefinitionMismatch {
                request: Req::OPCODE,
                response: Resp::OPCODE,
            });
        }

        let request_id = self.counters.next_request_id();
        let sequence_no = self.counters.next_sequence_no();
        let payload = request.encode_payload()?;

        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            Req::KIND,
            IpcFrameFlags::NONE,
            Req::OPCODE,
            IpcStatus::Ok,
            request_id,
            sequence_no,
            payload,
        )?;

        let response = self.client.request(&frame).await?;
        self.validate_common(&response)?;

        match response.kind() {
            IpcFrameKind::Response => {}
            
            IpcFrameKind::Error => {
                return Err(SyncIpcEndpointError::RemoteError {
                    status: response.status(),
                    payload: response.payload().clone(),
                });
            }
            
            found => {
                return Err(SyncIpcEndpointError::UnexpectedKind {
                    expected: IpcFrameKind::Response,
                    found,
                });
            }
        }

        if response.request_id() != request_id {
            return Err(SyncIpcEndpointError::UnexpectedRequestId {
                expected: request_id,
                found: response.request_id(),
            });
        }

        if response.opcode() != Req::OPCODE {
            return Err(SyncIpcEndpointError::UnexpectedOpcode {
                expected: Req::OPCODE,
                found: response.opcode(),
            });
        }

        if !response.status().is_success() {
            return Err(SyncIpcEndpointError::UnexpectedStatus(response.status()));
        }

        Resp::decode_payload(response.payload()).map_err(Into::into)
    }

    /// Odbiera typowane żądanie od drugiej strony połączenia.
    pub async fn receive_request<Req>(&mut self) -> Result<InboundRequest<Req>, SyncIpcEndpointError> where
        Req: IpcRequestMessage 
    {
        let frame = self.client.receive_frame().await?;
        self.validate_common(&frame)?;

        if frame.kind() != IpcFrameKind::Request {
            return Err(SyncIpcEndpointError::UnexpectedKind {
                expected: IpcFrameKind::Request,
                found: frame.kind(),
            });
        }

        if frame.opcode() != Req::OPCODE {
            return Err(SyncIpcEndpointError::UnexpectedOpcode {
                expected: Req::OPCODE,
                found: frame.opcode(),
            });
        }

        if frame.request_id() == 0 {
            return Err(SyncIpcEndpointError::InvalidRequestId(frame.request_id()));
        }

        if frame.status() != IpcStatus::Ok {
            return Err(SyncIpcEndpointError::UnexpectedStatus(frame.status()));
        }

        let message = Req::decode_payload(frame.payload())?;

        let meta = RequestMeta {
            magic: frame.magic(),
            version: frame.version(),
            opcode: frame.opcode(),
            request_id: frame.request_id(),
            sequence_no: frame.sequence_no(),
        };

        Ok(InboundRequest { meta, message })
    }

    /// Wysyła odpowiedź sukcesu na wcześniej odebrane żądanie.
    pub async fn send_response<Resp>(&mut self, request_meta: &RequestMeta, response: &Resp) -> Result<(), SyncIpcEndpointError>
        where Resp: IpcResponseMessage 
    {
        if response_opcode_mismatch::<Resp>(request_meta.opcode) {
            return Err(SyncIpcEndpointError::MessageDefinitionMismatch {
                request: request_meta.opcode,
                response: Resp::OPCODE,
            });
        }

        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            Resp::KIND,
            IpcFrameFlags::NONE,
            Resp::OPCODE,
            IpcStatus::Ok,
            request_meta.request_id,
            self.counters.next_sequence_no(),
            response.encode_payload()?,
        )?;

        self.client.send_frame(&frame).await?;

        Ok(())
    }

    /// Wysyła odpowiedź błędną na wcześniej odebrane żądanie.
    pub async fn send_error(&mut self, request_meta: &RequestMeta, status: IpcStatus, payload: Bytes)
        -> Result<(), SyncIpcEndpointError> 
    {
        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Error,
            IpcFrameFlags::NONE,
            request_meta.opcode,
            status,
            request_meta.request_id,
            self.counters.next_sequence_no(),
            payload,
        )?;

        self.client.send_frame(&frame).await?;

        Ok(())
    }

    fn validate_common(&self, frame: &IpcFrame) -> Result<(), SyncIpcEndpointError> {
        if frame.magic() != RGIPC_MAGIC {
            return Err(SyncIpcEndpointError::InvalidMagic {
                expected: RGIPC_MAGIC,
                found: frame.magic(),
            });
        }

        if frame.version() != RGIPC_VERSION {
            return Err(SyncIpcEndpointError::UnsupportedVersion {
                expected: RGIPC_VERSION,
                found: frame.version(),
            });
        }

        Ok(())
    }
}

fn response_opcode_mismatch<Resp>(request_opcode: IpcOpcode) -> bool where Resp: IpcResponseMessage {
    Resp::OPCODE != request_opcode
}

#[cfg(test)]
mod sync_endpoint_tests {
    use bytes::Bytes;
    use tokio::io::duplex;

    use super::SyncIpcEndpoint;
    use crate::control_plane::types::ipc_status::IpcStatus;
    use crate::control_plane::types::ipc_opcode::IpcOpcode;
    use crate::control_plane::ipc::ipc_message::IpcMessage;
    use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
    use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
    use crate::control_plane::messages::requests::ping_request::PingRequest;
    use crate::control_plane::messages::responses::ping_response::PingResponse;
    use crate::control_plane::errors::sync_ipc_endpoint_error::SyncIpcEndpointError;
    use crate::control_plane::ipc::ipc_frame::{IpcFrame, RGIPC_MAGIC, RGIPC_VERSION};
    use crate::control_plane::messages::requests::get_network_interfaces_request::GetNetworkInterfacesRequest;
    use crate::control_plane::messages::responses::get_network_interfaces_response::{GetNetworkInterfacesResponse, NetworkInterfaceEntry};

    #[tokio::test]
    async fn send_builds_request_and_decodes_response() {
        let (client_stream, mut peer_stream) = duplex(2048);

        let peer = tokio::spawn(async move {
            let frame = IpcFrame::read_from(&mut peer_stream).await.unwrap();

            assert_eq!(frame.kind(), IpcFrameKind::Request);
            assert_eq!(frame.opcode(), IpcOpcode::Ping);
            assert_eq!(frame.status(), IpcStatus::Ok);

            let response = PingResponse {
                timestamp_ms: 10,
                peer_timestamp_ms: 20,
            };

            let response_frame = IpcFrame::new(
                RGIPC_MAGIC,
                RGIPC_VERSION,
                IpcFrameKind::Response,
                IpcFrameFlags::NONE,
                IpcOpcode::Ping,
                IpcStatus::Ok,
                frame.request_id(),
                1,
                response.encode_payload().unwrap(),
            ).unwrap();

            response_frame.write_to(&mut peer_stream).await.unwrap();
        });

        let mut endpoint = SyncIpcEndpoint::from_stream(client_stream);

        let response = endpoint.send::<PingRequest, PingResponse>(&PingRequest { timestamp_ms: 10 })
            .await.unwrap();

        peer.await.unwrap();

        assert_eq!(
            response,
            PingResponse {
                timestamp_ms: 10,
                peer_timestamp_ms: 20
            }
        );
    }

    #[tokio::test]
    async fn receive_request_and_send_response_round_trip() {
        let (endpoint_stream, mut peer_stream) = duplex(4096);

        let peer = tokio::spawn(async move {
            let request = IpcFrame::new(
                RGIPC_MAGIC,
                RGIPC_VERSION,
                IpcFrameKind::Request,
                IpcFrameFlags::NONE,
                IpcOpcode::GetNetworkInterfaces,
                IpcStatus::Ok,
                55,
                1,
                GetNetworkInterfacesRequest.encode_payload().unwrap(),
            ).unwrap();

            request.write_to(&mut peer_stream).await.unwrap();

            let response = IpcFrame::read_from(&mut peer_stream).await.unwrap();

            assert_eq!(response.kind(), IpcFrameKind::Response);
            assert_eq!(response.opcode(), IpcOpcode::GetNetworkInterfaces);
            assert_eq!(response.request_id(), 55);

            GetNetworkInterfacesResponse::decode_payload(response.payload()).unwrap()
        });

        let mut endpoint = SyncIpcEndpoint::from_stream(endpoint_stream);

        let inbound = endpoint.receive_request::<GetNetworkInterfacesRequest>()
            .await.unwrap();

        let response = GetNetworkInterfacesResponse {
            interfaces: vec![NetworkInterfaceEntry {
                name: "eth0".to_string(),
                index: 2,
                is_up: true,
                mtu: 1500,
                mac: vec![1, 2, 3, 4, 5, 6],
                ips: vec!["10.0.0.1".to_string()],
            }],
        };

        endpoint.send_response(&inbound.meta, &response).await.unwrap();

        let received = peer.await.unwrap();

        assert_eq!(received, response);
    }

    #[tokio::test]
    async fn send_rejects_remote_error_frame() {
        let (client_stream, mut peer_stream) = duplex(2048);

        let peer = tokio::spawn(async move {
            let frame = IpcFrame::read_from(&mut peer_stream).await.unwrap();
            
            let error_frame = IpcFrame::new(
                RGIPC_MAGIC,
                RGIPC_VERSION,
                IpcFrameKind::Error,
                IpcFrameFlags::NONE,
                IpcOpcode::Ping,
                IpcStatus::ErrInternal,
                frame.request_id(),
                1,
                Bytes::from_static(b"err"),
            ).unwrap();
            
            error_frame.write_to(&mut peer_stream).await.unwrap();
        });

        let mut endpoint = SyncIpcEndpoint::from_stream(client_stream);
        
        let err = endpoint.send::<PingRequest, PingResponse>(&PingRequest { timestamp_ms: 1 })
            .await.unwrap_err();

        peer.await.unwrap();

        assert!(matches!(
            err,
            SyncIpcEndpointError::RemoteError {
                status: IpcStatus::ErrInternal,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn receive_request_rejects_wrong_kind() {
        let (endpoint_stream, mut peer_stream) = duplex(1024);

        let peer = tokio::spawn(async move {
            let frame = IpcFrame::new(
                RGIPC_MAGIC,
                RGIPC_VERSION,
                IpcFrameKind::Event,
                IpcFrameFlags::NONE,
                IpcOpcode::Heartbeat,
                IpcStatus::Ok,
                0,
                1,
                Bytes::new(),
            ).unwrap();
            
            frame.write_to(&mut peer_stream).await.unwrap();
        });

        let mut endpoint = SyncIpcEndpoint::from_stream(endpoint_stream);
        
        let err = endpoint.receive_request::<GetNetworkInterfacesRequest>()
            .await.unwrap_err();

        peer.await.unwrap();

        assert!(matches!(
            err,
            SyncIpcEndpointError::UnexpectedKind {
                expected: IpcFrameKind::Request,
                found: IpcFrameKind::Event
            }
        ));
    }
}
