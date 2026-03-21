use tokio::net::UnixStream;
use tracing::{debug, trace, warn};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::control_plane::ipc::ipc_frame::IpcFrame;
use crate::control_plane::logging::payload_preview_hex;
use crate::control_plane::errors::ipc_frame_error::IpcFrameError;
use crate::control_plane::errors::ipc_client_error::IpcClientError;

/// Niskopoziomowy klient IPC obsługujący dokładnie jedno połączenie.
pub struct IpcClient<S = UnixStream> {
    stream: S,
}

impl IpcClient<UnixStream> {
    /// Otwiera połączenie z pojedynczym gniazdem UDS wykorzystywanym przez IPC.
    pub async fn connect(socket_path: &str) -> Result<Self, IpcClientError> {
        debug!(socket = socket_path, "Opening low-level IPC client connection");
        
        let stream = UnixStream::connect(socket_path).await.map_err(IpcClientError::Connect)?;

        debug!(socket = socket_path, "Opened low-level IPC client connection");

        Ok(Self { stream })
    }
}

impl<S> IpcClient<S> where S: AsyncRead + AsyncWrite + Unpin {
    /// Tworzy klienta na bazie już przygotowanego strumienia.
    pub(crate) fn from_stream(stream: S) -> Self {
        Self { stream }
    }

    /// Wysyła jedną ramkę do zdalnej strony.
    pub async fn send_frame(&mut self, frame: &IpcFrame) -> Result<(), IpcClientError> {
        debug!(
            kind = ?frame.kind(),
            opcode = ?frame.opcode(),
            request_id = frame.request_id(),
            sequence_no = frame.sequence_no(),
            payload_len = frame.payload_length(),
            "Sending IPC frame"
        );
        
        trace!(
            kind = ?frame.kind(),
            opcode = ?frame.opcode(),
            status = ?frame.status(),
            request_id = frame.request_id(),
            sequence_no = frame.sequence_no(),
            payload_len = frame.payload_length(),
            payload_preview_hex = %payload_preview_hex(frame.payload(), 32),
            "Sending IPC frame details"
        );
        
        frame.write_to(&mut self.stream).await.map_err(IpcClientError::Io)
    }

    /// Odbiera jedną kompletną ramkę z połączenia.
    pub async fn receive_frame(&mut self) -> Result<IpcFrame, IpcClientError> {
        let frame = IpcFrame::read_from(&mut self.stream).await.map_err(Self::map_frame_error)?;

        debug!(
            kind = ?frame.kind(),
            opcode = ?frame.opcode(),
            request_id = frame.request_id(),
            sequence_no = frame.sequence_no(),
            payload_len = frame.payload_length(),
            "Received IPC frame"
        );
        
        trace!(
            kind = ?frame.kind(),
            opcode = ?frame.opcode(),
            status = ?frame.status(),
            request_id = frame.request_id(),
            sequence_no = frame.sequence_no(),
            payload_len = frame.payload_length(),
            payload_preview_hex = %payload_preview_hex(frame.payload(), 32),
            "Received IPC frame details"
        );

        Ok(frame)
    }

    /// Wysyła ramkę i od razu oczekuje na następną ramkę odpowiedzi.
    pub async fn request(&mut self, frame: &IpcFrame) -> Result<IpcFrame, IpcClientError> {
        debug!(
            opcode = ?frame.opcode(),
            request_id = frame.request_id(),
            sequence_no = frame.sequence_no(),
            "Executing IPC request roundtrip"
        );
        
        self.send_frame(frame).await?;

        self.receive_frame().await
    }

    /// Mapuje błędy warstwy ramki na błędy klienta transportowego.
    fn map_frame_error(err: IpcFrameError) -> IpcClientError {
        match err {
            IpcFrameError::TruncatedField { field } => {
                warn!(field, "Reached end of stream while decoding IPC frame field");
                IpcClientError::EndOfStream { field }
            }
            
            IpcFrameError::IncompletePayload { .. } => {
                warn!("Reached end of stream while reading IPC frame payload");
                IpcClientError::EndOfStream { field: "payload" }
            }
            
            IpcFrameError::Io { kind } => {
                warn!(io_kind = ?kind, "IPC client I/O error while decoding frame");
                IpcClientError::Io(std::io::Error::from(kind))
            }
            
            other => IpcClientError::Frame(other),
        }
    }
}

#[cfg(test)]
mod ipc_client_tests {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::IpcClient;
    use crate::control_plane::types::ipc_opcode::IpcOpcode;
    use crate::control_plane::types::ipc_status::IpcStatus;
    use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
    use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
    use crate::control_plane::errors::ipc_client_error::IpcClientError;
    use crate::control_plane::ipc::ipc_frame::{IpcFrame, RGIPC_MAGIC, RGIPC_VERSION};

    #[tokio::test]
    async fn send_frame_writes_encoded_frame() {
        let (client_stream, mut server_stream) = duplex(1024);

        let expected = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Request,
            IpcFrameFlags::ACK_REQUIRED,
            IpcOpcode::Ping,
            IpcStatus::Ok,
            9,
            10,
            Bytes::from_static(b"abc"),
        ).unwrap();

        let expected_bytes = expected.encode();
        let expected_len = expected_bytes.len();

        let server = tokio::spawn(async move {
            let mut raw = vec![0u8; expected_len];
            
            server_stream.read_exact(&mut raw).await.unwrap();
            
            raw
        });

        let mut client = IpcClient::from_stream(client_stream);
        
        client.send_frame(&expected).await.unwrap();

        let raw = server.await.unwrap();

        assert_eq!(raw, expected_bytes);
    }

    #[tokio::test]
    async fn receive_frame_reads_single_frame_from_stream() {
        let (client_stream, mut server_stream) = duplex(1024);

        let response = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Response,
            IpcFrameFlags::NONE,
            IpcOpcode::GetStatus,
            IpcStatus::Ok,
            15,
            16,
            Bytes::from_static(b"ok"),
        ).unwrap();

        let response_bytes = response.encode();

        let server =
            tokio::spawn(async move { server_stream.write_all(&response_bytes).await.unwrap() });

        let mut client = IpcClient::from_stream(client_stream);

        let frame = client.receive_frame().await.unwrap();

        server.await.unwrap();

        assert_eq!(frame, response);
    }

    #[tokio::test]
    async fn request_writes_then_reads_response() {
        let (client_stream, mut server_stream) = duplex(1024);

        let request = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Request,
            IpcFrameFlags::NONE,
            IpcOpcode::GetNetworkInterfaces,
            IpcStatus::Ok,
            99,
            1,
            Bytes::from_static(b"ping"),
        ).unwrap();

        let response = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Response,
            IpcFrameFlags::NONE,
            IpcOpcode::GetNetworkInterfaces,
            IpcStatus::Ok,
            99,
            2,
            Bytes::from_static(b"pong"),
        ).unwrap();

        let request_bytes = request.encode();
        let request_bytes_for_server = request_bytes.clone();
        let response_bytes = response.encode();

        let server = tokio::spawn(async move {
            let mut raw = vec![0u8; request_bytes_for_server.len()];
            server_stream.read_exact(&mut raw).await.unwrap();
            server_stream.write_all(&response_bytes).await.unwrap();
            raw
        });

        let mut client = IpcClient::from_stream(client_stream);
        
        let received = client.request(&request).await.unwrap();

        let raw_request = server.await.unwrap();

        assert_eq!(raw_request, request_bytes);
        assert_eq!(received, response);
    }

    #[tokio::test]
    async fn receive_frame_reports_truncated_payload() {
        let (client_stream, mut server_stream) = duplex(1024);

        let server = tokio::spawn(async move {
            let raw = [
                0x01, // magic
                0x01, // version
                0x02, // kind
                0x00, // flags
                0x01, // opcode
                0x00, // status
                0x01, // request_id
                0x01, // sequence_no
                0x03, // payload_length
                b'a', b'b',
            ];
            server_stream.write_all(&raw).await.unwrap();
        });

        let mut client = IpcClient::from_stream(client_stream);
        let err = client.receive_frame().await.unwrap_err();

        server.await.unwrap();

        assert!(matches!(
            err,
            IpcClientError::EndOfStream { field: "payload" }
        ));
    }
}
