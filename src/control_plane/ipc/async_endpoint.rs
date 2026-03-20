use tokio::net::UnixStream;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::control_plane::ipc::ipc_client::IpcClient;
use crate::control_plane::types::ipc_status::IpcStatus;
use crate::control_plane::ipc::ipc_counters::IpcCounters;
use crate::control_plane::ipc::ipc_message::IpcEventMessage;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::ipc::ipc_frame::{IpcFrame, RGIPC_MAGIC, RGIPC_VERSION};
use crate::control_plane::errors::async_ipc_endpoint_error::AsyncIpcEndpointError;

/// Endpoint obsługujący wysyłkę i odbiór eventów IPC.
pub struct AsyncIpcEndpoint<S = UnixStream> {
    client: IpcClient<S>,
    counters: IpcCounters,
}

impl AsyncIpcEndpoint<UnixStream> {
    /// Otwiera połączenie z kanałem asynchronicznym IPC.
    pub async fn connect(socket_path: &str) -> Result<Self, AsyncIpcEndpointError> {
        let client = IpcClient::connect(socket_path).await?;

        Ok(Self {
            client,
            counters: IpcCounters::default(),
        })
    }
}

impl<S> AsyncIpcEndpoint<S> where S: AsyncRead + AsyncWrite + Unpin
{
    /// Tworzy endpoint z już przygotowanego strumienia.
    pub(crate) fn from_stream(stream: S) -> Self {
        Self {
            client: IpcClient::from_stream(stream),
            counters: IpcCounters::default(),
        }
    }

    /// Wysyła typowany event do zdalnej strony.
    pub async fn send_event<E>(&mut self, event: &E, flags: IpcFrameFlags) -> Result<(), AsyncIpcEndpointError>
        where E: IpcEventMessage 
    {
        self.send_encoded_event(E::OPCODE, flags, event.encode_payload()?).await
    }

    /// Wysyła już zakodowany event do zdalnej strony.
    pub async fn send_encoded_event(
        &mut self,
        opcode: IpcOpcode,
        flags: IpcFrameFlags,
        payload: bytes::Bytes,
    ) -> Result<(), AsyncIpcEndpointError> {
        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Event,
            flags,
            opcode,
            IpcStatus::Ok,
            0,
            self.counters.next_sequence_no(),
            payload,
        )?;

        self.client.send_frame(&frame).await?;

        Ok(())
    }

    /// Odbiera i dekoduje typowany event od zdalnej strony.
    pub async fn receive_event<E>(&mut self) -> Result<E, AsyncIpcEndpointError> where E: IpcEventMessage {
        let frame = self.client.receive_frame().await?;
        
        self.validate_common(&frame)?;

        if frame.kind() != IpcFrameKind::Event {
            return Err(AsyncIpcEndpointError::UnexpectedKind {
                expected: IpcFrameKind::Event,
                found: frame.kind(),
            });
        }

        if frame.opcode() != E::OPCODE {
            return Err(AsyncIpcEndpointError::UnexpectedOpcode {
                expected: E::OPCODE,
                found: frame.opcode(),
            });
        }

        if frame.request_id() != 0 {
            return Err(AsyncIpcEndpointError::InvalidRequestId(frame.request_id()));
        }

        if frame.status() != IpcStatus::Ok {
            return Err(AsyncIpcEndpointError::UnexpectedStatus(frame.status()));
        }

        E::decode_payload(frame.payload()).map_err(Into::into)
    }

    fn validate_common(&self, frame: &IpcFrame) -> Result<(), AsyncIpcEndpointError> {
        if frame.magic() != RGIPC_MAGIC {
            return Err(AsyncIpcEndpointError::InvalidMagic {
                expected: RGIPC_MAGIC,
                found: frame.magic(),
            });
        }

        if frame.version() != RGIPC_VERSION {
            return Err(AsyncIpcEndpointError::UnsupportedVersion {
                expected: RGIPC_VERSION,
                found: frame.version(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod async_endpoint_tests {
    use tokio::io::duplex;

    use super::AsyncIpcEndpoint;
    use crate::control_plane::types::ipc_status::IpcStatus;
    use crate::control_plane::types::ipc_opcode::IpcOpcode;
    use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
    use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
    use crate::control_plane::ipc::ipc_message::{FirewallMode, IpcMessage};
    use crate::control_plane::messages::events::heartbeat_event::HeartbeatEvent;
    use crate::control_plane::ipc::ipc_frame::{IpcFrame, RGIPC_MAGIC, RGIPC_VERSION};
    use crate::control_plane::errors::async_ipc_endpoint_error::AsyncIpcEndpointError;

    #[tokio::test]
    async fn send_event_writes_event_frame() {
        let (endpoint_stream, mut peer_stream) = duplex(2048);

        let peer =
            tokio::spawn(async move { IpcFrame::read_from(&mut peer_stream).await.unwrap() });

        let mut endpoint = AsyncIpcEndpoint::from_stream(endpoint_stream);
        
        let event = HeartbeatEvent {
            timestamp_ms: 1,
            mode: FirewallMode::Normal,
            loaded_revision_id: 2,
            policy_hash: 3,
            uptime_sec: 4,
            last_error_code: 5,
        };

        endpoint.send_event(&event, IpcFrameFlags::CRITICAL).await.unwrap();

        let frame = peer.await.unwrap();
        
        assert_eq!(frame.kind(), IpcFrameKind::Event);
        assert_eq!(frame.opcode(), IpcOpcode::Heartbeat);
        assert_eq!(frame.request_id(), 0);
        assert_eq!(frame.flags(), IpcFrameFlags::CRITICAL);
    }

    #[tokio::test]
    async fn receive_event_decodes_payload() {
        let (endpoint_stream, mut peer_stream) = duplex(2048);

        let expected = HeartbeatEvent {
            timestamp_ms: 1,
            mode: FirewallMode::Emergency,
            loaded_revision_id: 2,
            policy_hash: 3,
            uptime_sec: 4,
            last_error_code: 5,
        };
        
        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Event,
            IpcFrameFlags::NONE,
            IpcOpcode::Heartbeat,
            IpcStatus::Ok,
            0,
            1,
            expected.encode_payload().unwrap(),
        ).unwrap();

        let peer = tokio::spawn(async move { frame.write_to(&mut peer_stream).await.unwrap() });

        let mut endpoint = AsyncIpcEndpoint::from_stream(endpoint_stream);
        let received = endpoint.receive_event::<HeartbeatEvent>().await.unwrap();

        peer.await.unwrap();
        
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn receive_event_rejects_wrong_kind() {
        let (endpoint_stream, mut peer_stream) = duplex(2048);

        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Response,
            IpcFrameFlags::NONE,
            IpcOpcode::Heartbeat,
            IpcStatus::Ok,
            0,
            1,
            HeartbeatEvent {
                timestamp_ms: 1,
                mode: FirewallMode::Normal,
                loaded_revision_id: 2,
                policy_hash: 3,
                uptime_sec: 4,
                last_error_code: 5,
            }.encode_payload().unwrap(),
        ).unwrap();

        let peer = tokio::spawn(async move { frame.write_to(&mut peer_stream).await.unwrap() });

        let mut endpoint = AsyncIpcEndpoint::from_stream(endpoint_stream);
        
        let err = endpoint.receive_event::<HeartbeatEvent>().await.unwrap_err();

        peer.await.unwrap();

        assert!(matches!(
            err,
            AsyncIpcEndpointError::UnexpectedKind {
                expected: IpcFrameKind::Event,
                found: IpcFrameKind::Response
            }
        ));
    }
}
