use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::data_plane::ips::ips::Ips;
use crate::dpi::{AppProto, DpiClassifier, DpiContext};
use crate::events;

const INSPECT_BUF_CAP: usize = 16_384;
const CHUNK_SIZE: usize = 8_192;
const MAX_INSPECT_CHUNKS: u8 = 5;

/// Werdykt inspekcji IPS po analizie odszyfrowanego ruchu.
#[derive(Debug, Clone)]
pub enum IpsVerdict {
    Allow,
    Alert { signature_name: String, severity: String },
    Block { signature_name: String, severity: String },
}

/// Trait dla silnika IPS — kolega implementuje dopasowanie sygnatur.
pub trait IpsInspector: Send + Sync {
    fn inspect(&self, payload: &[u8], dpi_ctx: &DpiContext) -> IpsVerdict;
}

/// Placeholder IPS — przepuszcza wszystko. Zastapiony prawdziwym silnikiem.
pub struct NoopIpsInspector;

impl IpsInspector for NoopIpsInspector {
    fn inspect(&self, _payload: &[u8], _dpi_ctx: &DpiContext) -> IpsVerdict {
        IpsVerdict::Allow
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// Metadane sesji TLS potrzebne do logowania i eventow.
#[derive(Clone)]
pub struct SessionMeta {
    pub peer: SocketAddr,
    pub server: SocketAddr,
    pub sni: Option<String>,
    pub mode: InspectionMode,
}

#[derive(Debug, Clone, Copy)]
pub enum InspectionMode {
    Inbound,
    Outbound,
}

// Adapter IPS dla odszyfrowanego ruchu -- deleguje do Ips::inspect_decrypted.
pub struct DecryptedIpsInspector {
    ips: Arc<Ips>,
}

impl DecryptedIpsInspector {
    pub fn new(ips: Arc<Ips>) -> Self {
        Self { ips }
    }
}

impl IpsInspector for DecryptedIpsInspector {
    fn inspect(&self, payload: &[u8], dpi_ctx: &DpiContext) -> IpsVerdict {
        let app_proto = dpi_ctx.app_proto;
        // Porty z DpiContext -- src_port/dst_port ustawiane w relay
        let src_port = dpi_ctx.src_port.unwrap_or(0);
        let dst_port = dpi_ctx.dst_port.unwrap_or(0);

        match self.ips.inspect_decrypted(payload, app_proto, src_port, dst_port) {
            crate::data_plane::ips::ips::IpsVerdict::Allow => IpsVerdict::Allow,
            crate::data_plane::ips::ips::IpsVerdict::Alert(msg) => IpsVerdict::Alert {
                signature_name: msg,
                severity: "medium".to_string(),
            },
            crate::data_plane::ips::ips::IpsVerdict::Block(msg) => IpsVerdict::Block {
                signature_name: msg,
                severity: "high".to_string(),
            },
        }
    }
}

/// Relay z inspekcja DPI/IPS na odszyfrowanym ruchu TLS.
pub struct InspectionRelay {
    ips: Arc<dyn IpsInspector>,
}

impl InspectionRelay {
    pub fn new(ips: Arc<dyn IpsInspector>) -> Self {
        Self { ips }
    }

    /// Bidirectional relay z inspekcją obu kierunków.
    pub async fn relay_bidirectional<CR, SW, SR, CW>(
        &self,
        client_read: CR,
        server_write: SW,
        server_read: SR,
        client_write: CW,
        meta: &SessionMeta,
    ) -> (u64, u64)
    where
        CR: AsyncRead + Unpin + Send + 'static,
        SW: AsyncWrite + Unpin + Send + 'static,
        SR: AsyncRead + Unpin + Send + 'static,
        CW: AsyncWrite + Unpin + Send + 'static,
    {
        let c2s_meta = meta.clone();
        let s2c_meta = meta.clone();
        let ips_c2s = Arc::clone(&self.ips);
        let ips_s2c = Arc::clone(&self.ips);

        let c2s = tokio::spawn(async move {
            relay_one_direction(client_read, server_write, Direction::ClientToServer, &c2s_meta, &*ips_c2s).await
        });
        let s2c = tokio::spawn(async move {
            relay_one_direction(server_read, client_write, Direction::ServerToClient, &s2c_meta, &*ips_s2c).await
        });

        let bytes_up = c2s.await.unwrap_or(0);
        let bytes_down = s2c.await.unwrap_or(0);

        (bytes_up, bytes_down)
    }
}

/// Relay jednego kierunku: buforuje poczatek, klasyfikuje, inspekcjonuje i streamuje fail-closed.
async fn relay_one_direction<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    meta: &SessionMeta,
    ips: &dyn IpsInspector,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let total_bytes: u64 = 0;
    let mut buffered = Vec::with_capacity(INSPECT_BUF_CAP);
    let mut chunks_seen: u8 = 0;
    let mut buf = [0u8; CHUNK_SIZE];
    let (src_port, dst_port) = ports_for_direction(meta, direction);

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => {
                if buffered.is_empty() {
                    return total_bytes;
                }
                let ctx = classify_or_fallback(&buffered, src_port, dst_port);
                return flush_buffered_and_continue(
                    &mut reader,
                    &mut writer,
                    &buffered,
                    &ctx,
                    meta,
                    direction,
                    ips,
                    total_bytes,
                )
                .await;
            }
            Ok(n) => n,
            Err(_) => return total_bytes,
        };

        buffered.extend_from_slice(&buf[..n]);
        chunks_seen += 1;

        let inspect_slice = inspection_slice(&buffered);
        if let Some(ctx) = classify_with_ports(inspect_slice, src_port, dst_port) {
            return flush_buffered_and_continue(
                &mut reader,
                &mut writer,
                &buffered,
                &ctx,
                meta,
                direction,
                ips,
                total_bytes,
            )
            .await;
        }

        if chunks_seen >= MAX_INSPECT_CHUNKS || inspect_slice.len() >= INSPECT_BUF_CAP {
            let ctx = fallback_ctx(src_port, dst_port);
            return flush_buffered_and_continue(
                &mut reader,
                &mut writer,
                &buffered,
                &ctx,
                meta,
                direction,
                ips,
                total_bytes,
            )
            .await;
        }
    }
}

fn inspection_slice(buffered: &[u8]) -> &[u8] {
    &buffered[..buffered.len().min(INSPECT_BUF_CAP)]
}

fn classify_with_ports(payload: &[u8], src_port: u16, dst_port: u16) -> Option<DpiContext> {
    let mut ctx = DpiClassifier::try_classify(payload)?;
    ctx.decrypted = true;
    ctx.src_port = Some(src_port);
    ctx.dst_port = Some(dst_port);
    Some(ctx)
}

fn fallback_ctx(src_port: u16, dst_port: u16) -> DpiContext {
    DpiContext {
        app_proto: Some(AppProto::Unknown),
        decrypted: true,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        ..Default::default()
    }
}

fn classify_or_fallback(payload: &[u8], src_port: u16, dst_port: u16) -> DpiContext {
    classify_with_ports(inspection_slice(payload), src_port, dst_port)
        .unwrap_or_else(|| fallback_ctx(src_port, dst_port))
}

async fn flush_buffered_and_continue<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffered: &[u8],
    ctx: &DpiContext,
    meta: &SessionMeta,
    direction: Direction,
    ips: &dyn IpsInspector,
    mut total_bytes: u64,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if let Err(blocked) = handle_verdict(ips, buffered, ctx, meta, direction) {
        if blocked {
            return total_bytes;
        }
    }

    emit_classification_event(meta, ctx, direction);

    if writer.write_all(buffered).await.is_err() {
        return total_bytes;
    }
    total_bytes += buffered.len() as u64;

    stream_with_inspection(reader, writer, ctx, meta, direction, ips, total_bytes).await
}

async fn stream_with_inspection<R, W>(
    reader: &mut R,
    writer: &mut W,
    ctx: &DpiContext,
    meta: &SessionMeta,
    direction: Direction,
    ips: &dyn IpsInspector,
    mut total_bytes: u64,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; CHUNK_SIZE];

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => return total_bytes,
            Ok(n) => n,
            Err(_) => return total_bytes,
        };

        if let Err(blocked) = handle_verdict(ips, &buf[..n], ctx, meta, direction) {
            if blocked {
                return total_bytes;
            }
        }

        if writer.write_all(&buf[..n]).await.is_err() {
            return total_bytes;
        }
        total_bytes += n as u64;
    }
}

/// Sprawdza werdykt IPS i emituje eventy. Zwraca Err(true) jesli zablokowano.
fn handle_verdict(
    ips: &dyn IpsInspector,
    payload: &[u8],
    ctx: &DpiContext,
    meta: &SessionMeta,
    direction: Direction,
) -> Result<(), bool> {
    match ips.inspect(payload, ctx) {
        IpsVerdict::Allow => Ok(()),
        IpsVerdict::Alert { signature_name, severity } => {
            let log_id = Uuid::now_v7().to_string();
            tracing::warn!(
                peer = %meta.peer,
                server = %meta.server,
                signature = %signature_name,
                severity = %severity,
                log_id = %log_id,
                "Decrypted traffic IPS alert"
            );
            events::emit(events::Event::new(
                events::EventKind::DecryptedIpsMatch {
                    peer: meta.peer,
                    server: meta.server,
                    sni: meta.sni.clone(),
                    signature_name,
                    severity,
                    blocked: false,
                    direction,
                    mode: meta.mode,
                    log_id,
                },
            ));
            Ok(())
        }
        IpsVerdict::Block { signature_name, severity } => {
            let log_id = Uuid::now_v7().to_string();
            tracing::warn!(
                peer = %meta.peer,
                server = %meta.server,
                signature = %signature_name,
                severity = %severity,
                log_id = %log_id,
                "Decrypted traffic blocked by IPS"
            );
            events::emit(events::Event::new(
                events::EventKind::DecryptedIpsMatch {
                    peer: meta.peer,
                    server: meta.server,
                    sni: meta.sni.clone(),
                    signature_name,
                    severity,
                    blocked: true,
                    direction,
                    mode: meta.mode,
                    log_id,
                },
            ));
            Err(true)
        }
    }
}

// Mapowanie portow na kierunek -- ServerToClient ma odwrocone porty.
fn ports_for_direction(meta: &SessionMeta, direction: Direction) -> (u16, u16) {
    match direction {
        Direction::ClientToServer => (meta.peer.port(), meta.server.port()),
        Direction::ServerToClient => (meta.server.port(), meta.peer.port()),
    }
}

fn emit_classification_event(meta: &SessionMeta, ctx: &DpiContext, direction: Direction) {
    if let Some(ref proto) = ctx.app_proto {
        tracing::debug!(
            peer = %meta.peer,
            server = %meta.server,
            proto = %proto,
            direction = ?direction,
            "Decrypted traffic classified"
        );
        events::emit(events::Event::new(
            events::EventKind::DecryptedTrafficClassified {
                peer: meta.peer,
                server: meta.server,
                sni: meta.sni.clone(),
                app_proto: proto.to_string(),
                direction,
                mode: meta.mode,
            },
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::duplex;

    struct RecordingInspector {
        calls: Mutex<Vec<(Vec<u8>, bool)>>,
        verdict: Mutex<IpsVerdict>,
    }

    impl RecordingInspector {
        fn new(verdict: IpsVerdict) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                verdict: Mutex::new(verdict),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl IpsInspector for RecordingInspector {
        fn inspect(&self, payload: &[u8], dpi_ctx: &DpiContext) -> IpsVerdict {
            self.calls
                .lock()
                .unwrap()
                .push((payload.to_vec(), dpi_ctx.decrypted));
            self.verdict.lock().unwrap().clone()
        }
    }

    fn test_meta() -> SessionMeta {
        SessionMeta {
            peer: "10.0.0.1:12345".parse().unwrap(),
            server: "10.0.0.2:443".parse().unwrap(),
            sni: Some("example.com".into()),
            mode: InspectionMode::Outbound,
        }
    }

    #[tokio::test]
    async fn passthrough_forwards_all_data() {
        let ips = Arc::new(NoopIpsInspector);
        let relay = InspectionRelay::new(ips);
        let meta = test_meta();

        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBody content here";
        let (mut c2s_w, c2s_r) = duplex(1024);
        let (s2c_w, mut s2c_r) = duplex(1024);

        c2s_w.write_all(payload).await.unwrap();
        drop(c2s_w);

        let empty_payload = b"";
        let (mut s_empty_w, s_empty_r) = duplex(1024);
        let (c_empty_w, mut c_empty_r) = duplex(1024);

        s_empty_w.write_all(empty_payload).await.unwrap();
        drop(s_empty_w);

        let (up, down) = relay
            .relay_bidirectional(c2s_r, s2c_w, s_empty_r, c_empty_w, &meta)
            .await;

        assert_eq!(up, payload.len() as u64);
        assert_eq!(down, 0);

        let mut received = Vec::new();
        s2c_r.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, payload);

        let mut c_received = Vec::new();
        c_empty_r.read_to_end(&mut c_received).await.unwrap();
        assert!(c_received.is_empty());
    }

    #[tokio::test]
    async fn ips_block_stops_relay() {
        let ips = Arc::new(RecordingInspector::new(IpsVerdict::Block {
            signature_name: "test-sig".into(),
            severity: "high".into(),
        }));
        let ips_clone = Arc::clone(&ips);
        let relay = InspectionRelay::new(ips_clone);
        let meta = test_meta();

        let payload = b"GET /malicious HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        let trailing = b"this should not be forwarded";
        let (mut c_w, c_r) = duplex(4096);
        let (s_w, _s_r) = duplex(4096);

        c_w.write_all(payload).await.unwrap();
        c_w.write_all(trailing).await.unwrap();
        drop(c_w);

        let (mut empty_w, empty_r) = duplex(64);
        let (empty_w2, _empty_r2) = duplex(64);
        empty_w.shutdown().await.unwrap();

        let (up, _down) = relay
            .relay_bidirectional(c_r, s_w, empty_r, empty_w2, &meta)
            .await;

        assert!(up <= (payload.len() + trailing.len()) as u64);
        assert!(ips.call_count() > 0);
    }

    #[tokio::test]
    async fn ips_block_prevents_buffer_forward() {
        let ips = Arc::new(RecordingInspector::new(IpsVerdict::Block {
            signature_name: "test-sig".into(),
            severity: "high".into(),
        }));
        let relay = InspectionRelay::new(ips);
        let meta = test_meta();

        let payload = b"GET /blocked HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        let (mut c_w, c_r) = duplex(1024);
        let (s_w, mut s_r) = duplex(1024);

        c_w.write_all(payload).await.unwrap();
        drop(c_w);

        let (mut empty_w, empty_r) = duplex(64);
        let (empty_w2, _empty_r2) = duplex(64);
        empty_w.shutdown().await.unwrap();

        let (up, _down) = relay
            .relay_bidirectional(c_r, s_w, empty_r, empty_w2, &meta)
            .await;

        let mut forwarded = Vec::new();
        s_r.read_to_end(&mut forwarded).await.unwrap();

        assert_eq!(up, 0);
        assert!(forwarded.is_empty());
    }

    #[tokio::test]
    async fn ips_receives_decrypted_flag() {
        let ips = Arc::new(RecordingInspector::new(IpsVerdict::Allow));
        let ips_clone = Arc::clone(&ips);
        let relay = InspectionRelay::new(ips_clone);
        let meta = test_meta();

        let payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n";
        let (mut c_w, c_r) = duplex(1024);
        let (s_w, _s_r) = duplex(1024);

        c_w.write_all(payload).await.unwrap();
        drop(c_w);

        let (mut empty_w, empty_r) = duplex(64);
        let (empty_w2, _empty_r2) = duplex(64);
        empty_w.shutdown().await.unwrap();

        relay
            .relay_bidirectional(c_r, s_w, empty_r, empty_w2, &meta)
            .await;

        let calls = ips.calls.lock().unwrap();
        assert!(!calls.is_empty());
        let (_payload, was_decrypted) = &calls[0];
        assert!(was_decrypted, "DpiContext.decrypted should be true");
    }

    #[tokio::test]
    async fn noop_inspector_always_allows() {
        let inspector = NoopIpsInspector;
        let ctx = DpiContext::default();
        match inspector.inspect(b"anything", &ctx) {
            IpsVerdict::Allow => {}
            other => panic!("Expected Allow, got {:?}", other),
        }
    }
}
