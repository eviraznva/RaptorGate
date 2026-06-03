use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::tls::session_meta::{Direction, InspectionMode, SessionMeta};

const FRAME_MAGIC: &[u8; 4] = b"RGDM";
const FRAME_VERSION: u8 = 1;
const FRAME_TYPE_DATA: u8 = 2;
const FRAME_HEADER_LEN: usize = 12;
const MIRROR_QUEUE_CAPACITY: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptionMirrorConfig {
    pub enabled: bool,
    pub target: Option<String>,
    pub include_client_to_server: bool,
    pub include_server_to_client: bool,
    pub forwarded_only: bool,
    pub max_session_bytes: u64,
}

impl Default for DecryptionMirrorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target: None,
            include_client_to_server: true,
            include_server_to_client: true,
            forwarded_only: true,
            max_session_bytes: 16 * 1024 * 1024,
        }
    }
}

pub struct MirrorFrame {
    frame_type: u8,
    session_id: Uuid,
    sequence: u64,
    direction: Direction,
    mode: InspectionMode,
    peer: SocketAddr,
    server: SocketAddr,
    sni: String,
    payload: Vec<u8>,
}

#[derive(Clone)]
pub struct DecryptionMirror {
    config: Arc<RwLock<DecryptionMirrorConfig>>,
    tx: mpsc::Sender<MirrorRecord>,
    session_bytes: Arc<Mutex<HashMap<Uuid, u64>>>,
}

pub(crate) struct MirrorRecord {
    target: String,
    frame: MirrorFrame,
}

impl DecryptionMirror {
    pub fn start(config: DecryptionMirrorConfig, cancel: CancellationToken) -> Self {
        let (tx, rx) = mpsc::channel(MIRROR_QUEUE_CAPACITY);
        let mirror = Self {
            config: Arc::new(RwLock::new(config)),
            tx,
            session_bytes: Arc::new(Mutex::new(HashMap::new())),
        };
        tokio::spawn(run_mirror_worker(rx, cancel));
        mirror
    }

    pub fn reload_config(&self, config: DecryptionMirrorConfig) {
        if let Ok(mut active) = self.config.write() {
            *active = config;
        }
        if let Ok(mut session_bytes) = self.session_bytes.lock() {
            session_bytes.clear();
        }
    }

    pub fn current_config(&self) -> DecryptionMirrorConfig {
        self.config
            .read()
            .map(|config| config.clone())
            .unwrap_or_default()
    }

    pub fn finish_session(&self, session_id: Uuid) {
        if let Ok(mut session_bytes) = self.session_bytes.lock() {
            session_bytes.remove(&session_id);
        }
    }

    pub fn record_data(&self, session_id: Uuid, sequence: u64, direction: Direction, meta: &SessionMeta, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        let config = self.current_config();
        let Some(target) = config.target.clone() else {
            return;
        };
        if !config.enabled || !direction_enabled(&config, direction) {
            return;
        }

        let payload = match self.limit_payload(session_id, payload, config.max_session_bytes) {
            Some(payload) => payload,
            None => return,
        };
        let frame = MirrorFrame::data(session_id, sequence, direction, meta, payload);
        if self.tx.try_send(MirrorRecord { target, frame }).is_err() {
            tracing::warn!(
                peer = %meta.peer,
                server = %meta.server,
                direction = ?direction,
                "decryption mirror queue full"
            );
        }
    }

    fn limit_payload<'a>(&self, session_id: Uuid, payload: &'a [u8], max_session_bytes: u64) -> Option<&'a [u8]> {
        if max_session_bytes == 0 {
            return Some(payload);
        }
        let mut session_bytes = self.session_bytes.lock().ok()?;
        let used = session_bytes.entry(session_id).or_insert(0);
        if *used >= max_session_bytes {
            return None;
        }
        let remaining = (max_session_bytes - *used) as usize;
        let allowed = payload.len().min(remaining);
        *used += allowed as u64;
        Some(&payload[..allowed])
    }

    #[cfg(test)]
    pub(crate) fn test_channel(config: DecryptionMirrorConfig) -> (Self, mpsc::Receiver<MirrorRecord>) {
        let (tx, rx) = mpsc::channel(MIRROR_QUEUE_CAPACITY);
        (
            Self {
                config: Arc::new(RwLock::new(config)),
                tx,
                session_bytes: Arc::new(Mutex::new(HashMap::new())),
            },
            rx,
        )
    }
}

impl MirrorFrame {
    pub fn data(session_id: Uuid, sequence: u64, direction: Direction, meta: &SessionMeta, payload: &[u8]) -> Self {
        Self {
            frame_type: FRAME_TYPE_DATA,
            session_id,
            sequence,
            direction,
            mode: meta.mode,
            peer: meta.peer,
            server: meta.server,
            sni: meta.sni.clone().unwrap_or_default(),
            payload: payload.to_vec(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let peer = self.peer.to_string();
        let server = self.server.to_string();
        let peer_bytes = peer.as_bytes();
        let server_bytes = server.as_bytes();
        let sni_bytes = self.sni.as_bytes();
        let body_len = 16 + 8 + 1 + 1 + 2 + 2 + 2 + 4
            + peer_bytes.len()
            + server_bytes.len()
            + sni_bytes.len()
            + self.payload.len();

        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body_len);
        out.extend_from_slice(FRAME_MAGIC);
        out.push(FRAME_VERSION);
        out.push(self.frame_type);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&(body_len as u32).to_be_bytes());
        out.extend_from_slice(self.session_id.as_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.push(direction_code(self.direction));
        out.push(mode_code(self.mode));
        out.extend_from_slice(&(peer_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&(server_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(peer_bytes);
        out.extend_from_slice(server_bytes);
        out.extend_from_slice(sni_bytes);
        out.extend_from_slice(&self.payload);
        out
    }

    #[cfg(test)]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

async fn run_mirror_worker(mut rx: mpsc::Receiver<MirrorRecord>, cancel: CancellationToken) {
    let mut stream: Option<TcpStream> = None;
    let mut active_target: Option<String> = None;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            record = rx.recv() => {
                let Some(record) = record else {
                    return;
                };
                if active_target.as_deref() != Some(record.target.as_str()) {
                    stream = None;
                    active_target = Some(record.target.clone());
                }
                let frame = record.frame.encode();
                write_mirror_frame(&mut stream, &record.target, &frame).await;
            }
        }
    }
}

async fn connect_mirror_target(target: &str) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect(target).await?;
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(target = %target, error = %e, "decryption mirror set TCP_NODELAY failed");
    }
    Ok(stream)
}

fn mirror_stream_closed(stream: &TcpStream, target: &str) -> bool {
    let mut probe = [0u8; 1];
    match stream.try_read(&mut probe) {
        Ok(0) => true,
        Ok(n) => {
            tracing::debug!(target = %target, bytes = n, "decryption mirror collector sent unexpected data");
            false
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock => false,
        Err(e) => {
            tracing::warn!(target = %target, error = %e, "decryption mirror collector connection check failed");
            true
        }
    }
}

async fn write_mirror_frame(stream: &mut Option<TcpStream>, target: &str, frame: &[u8]) {
    for attempt in 0..2 {
        if stream
            .as_ref()
            .is_some_and(|active| mirror_stream_closed(active, target))
        {
            *stream = None;
        }
        if stream.is_none() {
            *stream = match connect_mirror_target(target).await {
                Ok(stream) => Some(stream),
                Err(e) => {
                    tracing::warn!(target = %target, error = %e, "decryption mirror connect failed");
                    return;
                }
            };
        }
        let Some(active) = stream.as_mut() else {
            return;
        };
        match active.write_all(frame).await {
            Ok(()) => return,
            Err(e) => {
                tracing::warn!(
                    target = %target,
                    error = %e,
                    retrying = attempt == 0,
                    "decryption mirror write failed"
                );
                *stream = None;
            }
        }
    }
}

fn direction_enabled(config: &DecryptionMirrorConfig, direction: Direction) -> bool {
    match direction {
        Direction::ClientToServer => config.include_client_to_server,
        Direction::ServerToClient => config.include_server_to_client,
    }
}

fn direction_code(direction: Direction) -> u8 {
    match direction {
        Direction::ClientToServer => 1,
        Direction::ServerToClient => 2,
    }
}

fn mode_code(mode: InspectionMode) -> u8 {
    match mode {
        InspectionMode::Outbound => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;
    use tokio::time::{sleep, timeout, Duration};
    use uuid::Uuid;

    use crate::tls::session_meta::{Direction, InspectionMode, SessionMeta};

    fn test_meta() -> SessionMeta {
        SessionMeta {
            session_id: Uuid::now_v7(),
            peer: "192.168.20.10:51111".parse::<SocketAddr>().unwrap(),
            server: "142.250.203.132:443".parse::<SocketAddr>().unwrap(),
            sni: Some("www.google.com".into()),
            client_side_interface: Some("eth1".into()),
            server_side_interface: Some("eth0".into()),
            mode: InspectionMode::Outbound,
        }
    }

    #[test]
    fn data_frame_encoding_is_length_prefixed_and_preserves_plaintext() {
        let session_id = Uuid::from_u128(0x11223344556677889900aabbccddeeff);
        let frame = MirrorFrame::data(session_id, 7, Direction::ClientToServer, &test_meta(), b"GET / HTTP/1.1\r\n\r\n");

        let encoded = frame.encode();

        assert_eq!(&encoded[..8], b"RGDM\x01\x02\0\0");
        assert_eq!(u32::from_be_bytes(encoded[8..12].try_into().unwrap()) as usize, encoded.len() - 12);
        assert!(encoded.windows(18).any(|window| window == b"GET / HTTP/1.1\r\n\r\n"));
        assert!(encoded.windows(14).any(|window| window == b"www.google.com"));
    }

    #[test]
    fn mirror_config_defaults_to_disabled() {
        let config = DecryptionMirrorConfig::default();

        assert!(!config.enabled);
        assert!(config.target.is_none());
        assert!(config.include_client_to_server);
        assert!(config.include_server_to_client);
    }

    #[tokio::test]
    async fn mirror_stream_sends_plaintext_frame_to_tcp_collector() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let mirror = DecryptionMirror::start(
            DecryptionMirrorConfig {
                enabled: true,
                target: Some(target.to_string()),
                ..Default::default()
            },
            cancel.clone(),
        );
        let session_id = Uuid::from_u128(0x11223344556677889900aabbccddeeff);

        mirror.record_data(session_id, 1, Direction::ClientToServer, &test_meta(), b"GET /secret HTTP/1.1\r\n\r\n");

        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 512];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), tokio::io::AsyncReadExt::read(&mut stream, &mut buf))
            .await
            .unwrap()
            .unwrap();
        cancel.cancel();

        assert!(buf[..n].windows(24).any(|window| window == b"GET /secret HTTP/1.1\r\n\r\n"));
        assert!(buf[..n].windows(14).any(|window| window == b"www.google.com"));
    }

    #[tokio::test]
    async fn mirror_stream_retries_current_frame_after_stale_collector_disconnect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let mirror = DecryptionMirror::start(
            DecryptionMirrorConfig {
                enabled: true,
                target: Some(target.to_string()),
                ..Default::default()
            },
            cancel.clone(),
        );

        mirror.record_data(
            Uuid::from_u128(0x11111111111111111111111111111111),
            1,
            Direction::ClientToServer,
            &test_meta(),
            b"first frame",
        );

        let (mut stale_stream, _) = listener.accept().await.unwrap();
        let mut first = vec![0u8; 256];
        let first_len = timeout(Duration::from_secs(1), stale_stream.read(&mut first))
            .await
            .unwrap()
            .unwrap();
        assert!(first[..first_len].windows(11).any(|window| window == b"first frame"));
        drop(stale_stream);
        sleep(Duration::from_millis(50)).await;

        mirror.record_data(
            Uuid::from_u128(0x22222222222222222222222222222222),
            1,
            Direction::ClientToServer,
            &test_meta(),
            b"second frame",
        );

        let (mut reconnected_stream, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("mirror did not reconnect after stale collector disconnect")
            .unwrap();
        let mut second = vec![0u8; 256];
        let second_len = timeout(Duration::from_secs(1), reconnected_stream.read(&mut second))
            .await
            .unwrap()
            .unwrap();
        cancel.cancel();

        assert!(
            second[..second_len]
                .windows(12)
                .any(|window| window == b"second frame")
        );
    }

    #[test]
    fn record_data_applies_per_session_byte_limit() {
        let (mirror, mut rx) = DecryptionMirror::test_channel(DecryptionMirrorConfig {
            enabled: true,
            target: Some("collector.local:9000".into()),
            max_session_bytes: 5,
            ..Default::default()
        });
        let session_id = Uuid::from_u128(0x11223344556677889900aabbccddeeff);

        mirror.record_data(session_id, 1, Direction::ClientToServer, &test_meta(), b"abcdef");
        mirror.record_data(session_id, 2, Direction::ClientToServer, &test_meta(), b"ghijkl");

        let record = rx.try_recv().unwrap();
        assert_eq!(record.target, "collector.local:9000");
        assert_eq!(record.frame.payload(), b"abcde");
        assert!(rx.try_recv().is_err());

        mirror.finish_session(session_id);
        mirror.record_data(session_id, 3, Direction::ClientToServer, &test_meta(), b"xyz");
        let record = rx.try_recv().unwrap();
        assert_eq!(record.frame.payload(), b"xyz");
    }

    #[test]
    fn reload_config_changes_target_for_future_records() {
        let (mirror, mut rx) = DecryptionMirror::test_channel(DecryptionMirrorConfig::default());
        let session_id = Uuid::from_u128(0x11223344556677889900aabbccddeeff);

        mirror.record_data(session_id, 1, Direction::ClientToServer, &test_meta(), b"ignored");
        mirror.reload_config(DecryptionMirrorConfig {
            enabled: true,
            target: Some("127.0.0.1:9001".into()),
            ..Default::default()
        });
        mirror.record_data(session_id, 2, Direction::ClientToServer, &test_meta(), b"GET / HTTP/1.1\r\n\r\n");

        let record = rx.try_recv().unwrap();
        assert_eq!(record.target, "127.0.0.1:9001");
        assert_eq!(record.frame.payload(), b"GET / HTTP/1.1\r\n\r\n");
        assert!(rx.try_recv().is_err());
    }
}
