use tokio::net::UnixStream;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::control_plane::ipc::ipc_frame::IpcFrame;
use crate::control_plane::errors::ipc_frame_error::IpcFrameError;
use crate::control_plane::errors::ipc_client_error::IpcClientError;

/// Niskopoziomowy klient IPC obsługujący dokładnie jedno połączenie.
pub struct IpcClient<S = UnixStream> {
    stream: S,
}

impl IpcClient<UnixStream> {
    /// Otwiera połączenie z pojedynczym gniazdem UDS wykorzystywanym przez IPC.
    pub async fn connect(socket_path: &str) -> Result<Self, IpcClientError> {
        let stream = UnixStream::connect(socket_path).await.map_err(IpcClientError::Connect)?;

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
        frame.write_to(&mut self.stream).await.map_err(IpcClientError::Io)
    }

    /// Odbiera jedną kompletną ramkę z połączenia.
    pub async fn receive_frame(&mut self) -> Result<IpcFrame, IpcClientError> {
        IpcFrame::read_from(&mut self.stream).await.map_err(Self::map_frame_error)
    }

    /// Wysyła ramkę i od razu oczekuje na następną ramkę odpowiedzi.
    pub async fn request(&mut self, frame: &IpcFrame) -> Result<IpcFrame, IpcClientError> {
        self.send_frame(frame).await?;

        self.receive_frame().await
    }

    /// Mapuje błędy warstwy ramki na błędy klienta transportowego.
    fn map_frame_error(err: IpcFrameError) -> IpcClientError {
        match err {
            IpcFrameError::TruncatedField { field } => IpcClientError::EndOfStream { field },
            
            IpcFrameError::IncompletePayload { .. } => {
                IpcClientError::EndOfStream { field: "payload" }
            }
            
            IpcFrameError::Io { kind } => IpcClientError::Io(std::io::Error::from(kind)),
            
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
