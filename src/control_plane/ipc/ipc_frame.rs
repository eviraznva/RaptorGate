use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::control_plane::types::varint::VarInt;
use crate::control_plane::types::varlong::VarLong;
use crate::control_plane::types::ipc_status::IpcStatus;
use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;

pub(crate) use crate::control_plane::errors::ipc_frame_error::IpcFrameError;

/// Aktualna wersja formatu ramki `RGIPC`.
pub const RGIPC_VERSION: u32 = 1;
/// Stała identyfikująca protokół `RGIPC` na drucie.
pub const RGIPC_MAGIC: u32 = 0x5247_4950;

/// Reprezentacja pojedynczej ramki lokalnego protokołu IPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcFrame {
    magic: VarInt,
    version: VarInt,
    kind: IpcFrameKind,
    flags: IpcFrameFlags,
    opcode: IpcOpcode,
    status: IpcStatus,
    request_id: VarLong,
    sequence_no: VarLong,
    payload_length: VarInt,
    payload: Bytes,
}

impl IpcFrame {
    /// Buduje ramkę z gotowych pól logicznych i oblicza długość payloadu.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        magic: u32,
        version: u32,
        kind: IpcFrameKind,
        flags: IpcFrameFlags,
        opcode: IpcOpcode,
        status: IpcStatus,
        request_id: u64,
        sequence_no: u64,
        payload: impl Into<Bytes>,
    ) -> Result<Self, IpcFrameError>
    {
        let payload = payload.into();

        let payload_length = u32::try_from(payload.len())
            .map_err(|_| IpcFrameError::PayloadTooLarge(payload.len()))?;

        Ok(Self {
            magic: VarInt::new(magic),
            version: VarInt::new(version),
            kind,
            flags,
            opcode,
            status,
            request_id: VarLong::new(request_id),
            sequence_no: VarLong::new(sequence_no),
            payload_length: VarInt::new(payload_length),
            payload,
        })
    }

    /// Zwraca liczbę bajtów potrzebnych do zakodowania całej ramki.
    pub fn encoded_len(&self) -> usize {
        let kind = VarInt::new(self.kind.into());

        let flags = VarInt::new(self.flags.into());
        let opcode = VarInt::new(self.opcode.into());
        let status = VarInt::new(self.status.into());

        self.magic.encoded_len()
            + self.version.encoded_len()
            + kind.encoded_len()
            + flags.encoded_len()
            + opcode.encoded_len()
            + status.encoded_len()
            + self.request_id.encoded_len()
            + self.sequence_no.encoded_len()
            + self.payload_length.encoded_len()
            + self.payload.len()
    }

    /// Koduje ramkę do jednego bufora bajtów.
    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.encoded_len());

        Self::put_varint(&mut bytes, self.magic);
        Self::put_varint(&mut bytes, self.version);
        Self::put_varint(&mut bytes, VarInt::new(self.kind.into()));
        Self::put_varint(&mut bytes, VarInt::new(self.flags.into()));
        Self::put_varint(&mut bytes, VarInt::new(self.opcode.into()));
        Self::put_varint(&mut bytes, VarInt::new(self.status.into()));
        Self::put_varlong(&mut bytes, self.request_id);
        Self::put_varlong(&mut bytes, self.sequence_no);
        Self::put_varint(&mut bytes, self.payload_length);

        bytes.extend_from_slice(&self.payload);

        bytes.freeze()
    }

    /// Zapisuje zakodowaną ramkę bezpośrednio do strumienia.
    pub async fn write_to<W>(&self, writer: &mut W) -> std::io::Result<()> where W: AsyncWrite + Unpin {
        let encoded = self.encode();

        writer.write_all(&encoded).await
    }

    /// Odczytuje dokładnie jedną ramkę ze strumienia, pole po polu.
    pub async fn read_from<R>(reader: &mut R) -> Result<Self, IpcFrameError> where R: AsyncRead + Unpin {
        let magic = Self::read_varint_from(reader, "magic").await?;
        let version = Self::read_varint_from(reader, "version").await?;
        let kind = IpcFrameKind::try_from(Self::read_varint_from(reader, "kind").await?.get())?;
        let flags = IpcFrameFlags::try_from(Self::read_varint_from(reader, "flags").await?.get())?;
        let opcode = IpcOpcode::try_from(Self::read_varint_from(reader, "opcode").await?.get())?;
        let status = IpcStatus::try_from(Self::read_varint_from(reader, "status").await?.get())?;
        let request_id = Self::read_varlong_from(reader, "request_id").await?;
        let sequence_no = Self::read_varlong_from(reader, "sequence_no").await?;
        let payload_length = Self::read_varint_from(reader, "payload_length").await?;
        let payload = Self::read_payload_from(reader, payload_length.get() as usize).await?;

        Ok(Self {
            magic,
            version,
            kind,
            flags,
            opcode,
            status,
            request_id,
            sequence_no,
            payload_length,
            payload,
        })
    }

    /// Dekoduje ramkę z gotowego bufora i zwraca też liczbę zużytych bajtów.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), IpcFrameError> {
        let mut cursor = buf;

        let start_len = cursor.len();

        let magic = Self::decode_varint(&mut cursor, "magic")?;
        let version = Self::decode_varint(&mut cursor, "version")?;
        let kind = IpcFrameKind::try_from(Self::decode_varint(&mut cursor, "kind")?.get())?;
        let flags = IpcFrameFlags::try_from(Self::decode_varint(&mut cursor, "flags")?.get())?;
        let opcode = IpcOpcode::try_from(Self::decode_varint(&mut cursor, "opcode")?.get())?;
        let status = IpcStatus::try_from(Self::decode_varint(&mut cursor, "status")?.get())?;
        let request_id = Self::decode_varlong(&mut cursor, "request_id")?;
        let sequence_no = Self::decode_varlong(&mut cursor, "sequence_no")?;
        let payload_length = Self::decode_varint(&mut cursor, "payload_length")?;

        let declared_payload_len = payload_length.get() as usize;

        if cursor.len() < declared_payload_len {
            return Err(IpcFrameError::IncompletePayload {
                declared: declared_payload_len,
                available: cursor.len(),
            });
        }

        let payload = Bytes::copy_from_slice(&cursor[..declared_payload_len]);

        cursor = &cursor[declared_payload_len..];

        Ok((
            Self {
                magic,
                version,
                kind,
                flags,
                opcode,
                status,
                request_id,
                sequence_no,
                payload_length,
                payload,
            },
            start_len - cursor.len(),
        ))
    }

    /// Dekoduje ramkę z kursora i przesuwa go o długość odczytanej wiadomości.
    pub fn decode_cursor(cursor: &mut &[u8]) -> Result<Self, IpcFrameError> {
        let (frame, len) = Self::decode(cursor)?;

        *cursor = &cursor[len..];

        Ok(frame)
    }

    /// Zwraca wartość pola `magic`.
    pub fn magic(&self) -> u32 {
        self.magic.get()
    }

    /// Zwraca wartość pola `version`.
    pub fn version(&self) -> u32 {
        self.version.get()
    }

    /// Zwraca rodzaj ramki.
    pub fn kind(&self) -> IpcFrameKind {
        self.kind
    }

    /// Zwraca maskę flag ustawionych w ramce.
    pub fn flags(&self) -> IpcFrameFlags {
        self.flags
    }

    /// Zwraca kod operacji albo zdarzenia.
    pub fn opcode(&self) -> IpcOpcode {
        self.opcode
    }

    /// Zwraca kod statusu odpowiedzi lub błędu.
    pub fn status(&self) -> IpcStatus {
        self.status
    }

    /// Zwraca identyfikator korelacji żądania.
    pub fn request_id(&self) -> u64 {
        self.request_id.get()
    }

    /// Zwraca numer sekwencyjny wiadomości w ramach połączenia.
    pub fn sequence_no(&self) -> u64 {
        self.sequence_no.get()
    }

    /// Zwraca zadeklarowaną długość payloadu.
    pub fn payload_length(&self) -> u32 {
        self.payload_length.get()
    }

    /// Zwraca surowy payload ramki.
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    fn put_varint(bytes: &mut BytesMut, value: VarInt) {
        let mut buf = [0u8; VarInt::MAX_LEN];

        bytes.extend_from_slice(value.encode_into(&mut buf));
    }

    fn put_varlong(bytes: &mut BytesMut, value: VarLong) {
        let mut buf = [0u8; VarLong::MAX_LEN];

        bytes.extend_from_slice(value.encode_into(&mut buf));
    }

    fn decode_varint(cursor: &mut &[u8], field: &'static str) -> Result<VarInt, IpcFrameError> {
        VarInt::decode_cursor(cursor).ok_or(IpcFrameError::TruncatedField { field })
    }

    fn decode_varlong(cursor: &mut &[u8], field: &'static str) -> Result<VarLong, IpcFrameError> {
        VarLong::decode_cursor(cursor).ok_or(IpcFrameError::TruncatedField { field })
    }

    /// Odczytuje payload o długości zadeklarowanej wcześniej w nagłówku logicznym.
    async fn read_payload_from<R>(reader: &mut R, payload_len: usize) -> Result<Bytes, IpcFrameError>
        where R: AsyncRead + Unpin
    {
        let mut payload = vec![0u8; payload_len];
        let mut read = 0usize;

        while read < payload_len {
            match reader.read(&mut payload[read..]).await {
                Ok(0) => {
                    return Err(IpcFrameError::IncompletePayload {
                        declared: payload_len,
                        available: read,
                    });
                }
                Ok(n) => read += n,
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(IpcFrameError::IncompletePayload {
                        declared: payload_len,
                        available: read,
                    });
                }
                Err(err) => return Err(IpcFrameError::Io { kind: err.kind() }),
            }
        }

        Ok(Bytes::from(payload))
    }

    /// Odczytuje jedno pole `varint` ze strumienia.
    async fn read_varint_from<R>(reader: &mut R, field: &'static str) -> Result<VarInt, IpcFrameError> where
        R: AsyncRead + Unpin
    {
        let mut buf = [0u8; VarInt::MAX_LEN];

        for i in 0..VarInt::MAX_LEN {
            buf[i] = Self::read_byte_from(reader, field).await?;

            if buf[i] & 0x80 == 0 {
                return VarInt::decode(&buf[..=i])
                    .map(|(value, _)| value)
                    .ok_or(IpcFrameError::TruncatedField { field });
            }
        }

        Err(IpcFrameError::TruncatedField { field })
    }

    /// Odczytuje jedno pole `varlong` ze strumienia.
    async fn read_varlong_from<R>(reader: &mut R, field: &'static str) -> Result<VarLong, IpcFrameError> where
        R: AsyncRead + Unpin
    {
        let mut buf = [0u8; VarLong::MAX_LEN];

        for i in 0..VarLong::MAX_LEN {
            buf[i] = Self::read_byte_from(reader, field).await?;

            if buf[i] & 0x80 == 0 {
                return VarLong::decode(&buf[..=i])
                    .map(|(value, _)| value)
                    .ok_or(IpcFrameError::TruncatedField { field });
            }
        }

        Err(IpcFrameError::TruncatedField { field })
    }

    /// Odczytuje pojedynczy bajt pomocniczy używany przy dekodowaniu pól zmiennej długości.
    async fn read_byte_from<R>(reader: &mut R, field: &'static str) -> Result<u8, IpcFrameError> where R: AsyncRead + Unpin {
        match reader.read_u8().await {
            Ok(byte) => Ok(byte),

            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                Err(IpcFrameError::TruncatedField { field })
            }

            Err(err) => Err(IpcFrameError::Io { kind: err.kind() }),
        }
    }
}

impl Default for IpcFrame {
    fn default() -> Self {
        Self::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Request,
            IpcFrameFlags::NONE,
            IpcOpcode::Ping,
            IpcStatus::Ok,
            0,
            0,
            Bytes::new(),
        ).expect("the default IPC frame should be valid")
    }
}

#[cfg(test)]
mod ipc_frame_tests {
    use bytes::Bytes;
    use tokio::io::duplex;

    use crate::control_plane::types::ipc_status::IpcStatus;
    use crate::control_plane::types::ipc_opcode::IpcOpcode;
    use super::{IpcFrame, IpcFrameError, IpcFrameFlags, IpcFrameKind, RGIPC_MAGIC, RGIPC_VERSION};

    #[test]
    fn encode_decode_round_trip() {
        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Request,
            IpcFrameFlags::ACK_REQUIRED | IpcFrameFlags::CRITICAL,
            IpcOpcode::Heartbeat,
            IpcStatus::Ok,
            42,
            7,
            Bytes::from_static(b"hello"),
        ).unwrap();

        let encoded = frame.encode();

        let (decoded, used) = IpcFrame::decode(&encoded).unwrap();

        assert_eq!(decoded, frame);
        assert_eq!(used, encoded.len());
    }

    #[test]
    fn encoded_len_matches_serialized_size() {
        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Event,
            IpcFrameFlags::NONE,
            IpcOpcode::Ping,
            IpcStatus::Ok,
            1,
            1,
            Bytes::from_static(b"abc"),
        ).unwrap();

        assert_eq!(frame.encoded_len(), frame.encode().len());
    }

    #[test]
    fn decode_cursor_advances_slice() {
        let first = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Request,
            IpcFrameFlags::NONE,
            IpcOpcode::Ping,
            IpcStatus::Ok,
            11,
            1,
            Bytes::from_static(b"a"),
        ).unwrap();

        let second = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Response,
            IpcFrameFlags::NONE,
            IpcOpcode::GetStatus,
            IpcStatus::Ok,
            11,
            2,
            Bytes::from_static(b"bc"),
        ).unwrap();

        let mut raw = first.encode().to_vec();

        raw.extend_from_slice(&second.encode());

        let mut cursor = raw.as_slice();

        let decoded_first = IpcFrame::decode_cursor(&mut cursor).unwrap();
        let decoded_second = IpcFrame::decode_cursor(&mut cursor).unwrap();

        assert_eq!(decoded_first, first);
        assert_eq!(decoded_second, second);
        assert!(cursor.is_empty());
    }

    #[test]
    fn decode_rejects_truncated_header_field() {
        let err = IpcFrame::decode(&[0x80]).unwrap_err();

        assert_eq!(err, IpcFrameError::TruncatedField { field: "magic" });
    }

    #[test]
    fn decode_rejects_incomplete_payload() {
        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Request,
            IpcFrameFlags::NONE,
            IpcOpcode::Ping,
            IpcStatus::Ok,
            1,
            1,
            Bytes::from_static(b"abc"),
        ).unwrap();

        let mut encoded = frame.encode().to_vec();

        encoded.pop();

        let err = IpcFrame::decode(&encoded).unwrap_err();

        assert_eq!(
            err,
            IpcFrameError::IncompletePayload {
                declared: 3,
                available: 2
            }
        );
    }

    #[test]
    fn decode_rejects_invalid_kind() {
        let raw = [
            0x01, // magic
            0x01, // version
            0x09, // invalid kind
            0x00, // flags
            0x01, // opcode
            0x00, // status
            0x01, // request_id
            0x01, // sequence_no
            0x00, // payload_length
        ];

        let err = IpcFrame::decode(&raw).unwrap_err();

        assert_eq!(err, IpcFrameError::InvalidKind(9));
    }

    #[test]
    fn decode_rejects_invalid_flags() {
        let raw = [
            0x01, // magic
            0x01, // version
            0x02, // request
            0x08, // invalid flags
            0x01, // opcode
            0x00, // status
            0x01, // request_id
            0x01, // sequence_no
            0x00, // payload_length
        ];

        let err = IpcFrame::decode(&raw).unwrap_err();

        assert_eq!(err, IpcFrameError::InvalidFlags(0x08));
    }

    #[test]
    fn flags_support_combined_bits() {
        let flags = IpcFrameFlags::ACK_REQUIRED | IpcFrameFlags::CRITICAL;

        assert!(flags.contains(IpcFrameFlags::ACK_REQUIRED));
        assert!(flags.contains(IpcFrameFlags::CRITICAL));
        assert!(!flags.contains(IpcFrameFlags::NO_REPLY));
    }

    #[tokio::test]
    async fn write_to_and_read_from_round_trip() {
        let (mut writer, mut reader) = duplex(1024);

        let frame = IpcFrame::new(
            RGIPC_MAGIC,
            RGIPC_VERSION,
            IpcFrameKind::Response,
            IpcFrameFlags::ACK_REQUIRED,
            IpcOpcode::Heartbeat,
            IpcStatus::Ok,
            21,
            22,
            Bytes::from_static(b"payload"),
        ).unwrap();

        let expected = frame.clone();

        let write_task = tokio::spawn(async move { frame.write_to(&mut writer).await.unwrap() });

        let decoded = IpcFrame::read_from(&mut reader).await.unwrap();

        write_task.await.unwrap();

        assert_eq!(decoded, expected);
    }

    #[test]
    fn decode_rejects_invalid_opcode() {
        let raw = [
            0x01, // magic
            0x01, // version
            0x02, // request
            0x00, // flags
            0x09, // invalid opcode
            0x00, // status
            0x01, // request_id
            0x01, // sequence_no
            0x00, // payload_length
        ];

        let err = IpcFrame::decode(&raw).unwrap_err();

        assert_eq!(err, IpcFrameError::InvalidOpcode(0x09));
    }

    #[test]
    fn decode_rejects_invalid_status() {
        let raw = [
            0x01, // magic
            0x01, // version
            0x02, // request
            0x00, // flags
            0x01, // opcode
            0x63, // invalid status
            0x01, // request_id
            0x01, // sequence_no
            0x00, // payload_length
        ];

        let err = IpcFrame::decode(&raw).unwrap_err();

        assert_eq!(err, IpcFrameError::InvalidStatus(99));
    }
}
