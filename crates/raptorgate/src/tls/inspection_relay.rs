use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::dpi::{AppProto, DpiClassifier, DpiContext};
use crate::events;
use crate::tls::decrypted_chain::{
    DecryptedTrafficInspector, InspectionDisposition,
};

const INSPECT_BUF_CAP: usize = 16_384;
const CHUNK_SIZE: usize = 8_192;
const MAX_INSPECT_CHUNKS: u8 = 5;

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

/// Relay z inspekcja DPI/IPS na odszyfrowanym ruchu TLS.
pub struct InspectionRelay {
    inspector: Arc<dyn DecryptedTrafficInspector>,
}

impl InspectionRelay {
    pub fn new(inspector: Arc<dyn DecryptedTrafficInspector>) -> Self {
        Self { inspector }
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
        let inspector_c2s = Arc::clone(&self.inspector);
        let inspector_s2c = Arc::clone(&self.inspector);

        let c2s = tokio::spawn(async move {
            relay_one_direction(
                client_read,
                server_write,
                Direction::ClientToServer,
                &c2s_meta,
                inspector_c2s,
            )
            .await
        });
        let s2c = tokio::spawn(async move {
            relay_one_direction(
                server_read,
                client_write,
                Direction::ServerToClient,
                &s2c_meta,
                inspector_s2c,
            )
            .await
        });

        let bytes_up = c2s.await.unwrap_or(0);
        let bytes_down = s2c.await.unwrap_or(0);
        self.inspector.close_session(meta);

        (bytes_up, bytes_down)
    }
}

/// Relay jednego kierunku: buforuje poczatek, klasyfikuje, inspekcjonuje i streamuje fail-closed.
async fn relay_one_direction<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    meta: &SessionMeta,
    inspector: Arc<dyn DecryptedTrafficInspector>,
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
                    let _ = writer.shutdown().await;
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
                    &*inspector,
                    total_bytes,
                )
                .await;
            }
            Ok(n) => n,
            Err(_) => {
                let _ = writer.shutdown().await;
                return total_bytes;
            }
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
                &*inspector,
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
                &*inspector,
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
    inspector: &dyn DecryptedTrafficInspector,
    mut total_bytes: u64,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let decision = inspector.inspect(buffered, ctx, direction, meta).await;
    emit_ips_match_event(meta, &decision.ctx, direction);

    if matches!(decision.disposition, InspectionDisposition::Drop) {
        let _ = writer.shutdown().await;
        return total_bytes;
    }

    emit_classification_event(meta, &decision.ctx, direction);

    if writer.write_all(&decision.payload).await.is_err() {
        let _ = writer.shutdown().await;
        return total_bytes;
    }
    total_bytes += decision.payload.len() as u64;

    stream_with_inspection(reader, writer, &decision.ctx, meta, direction, inspector, total_bytes).await
}

async fn stream_with_inspection<R, W>(
    reader: &mut R,
    writer: &mut W,
    ctx: &DpiContext,
    meta: &SessionMeta,
    direction: Direction,
    inspector: &dyn DecryptedTrafficInspector,
    mut total_bytes: u64,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; CHUNK_SIZE];
    let mut current_ctx = ctx.clone();

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => {
                let _ = writer.shutdown().await;
                return total_bytes;
            }
            Ok(n) => n,
            Err(_) => {
                let _ = writer.shutdown().await;
                return total_bytes;
            }
        };

        let decision = inspector.inspect(&buf[..n], &current_ctx, direction, meta).await;
        emit_ips_match_event(meta, &decision.ctx, direction);

        if matches!(decision.disposition, InspectionDisposition::Drop) {
            let _ = writer.shutdown().await;
            return total_bytes;
        }

        if classification_changed(&current_ctx, &decision.ctx) {
            emit_classification_event(meta, &decision.ctx, direction);
        }
        current_ctx = decision.ctx.clone();

        if writer.write_all(&decision.payload).await.is_err() {
            let _ = writer.shutdown().await;
            return total_bytes;
        }
        total_bytes += decision.payload.len() as u64;
    }
}

fn emit_ips_match_event(
    meta: &SessionMeta,
    ctx: &DpiContext,
    direction: Direction,
) {
    let Some(ips_match) = ctx.ips_match.as_ref() else {
        return;
    };

    let log_id = Uuid::now_v7().to_string();
    tracing::warn!(
        peer = %meta.peer,
        server = %meta.server,
        signature = %ips_match.signature_name,
        severity = %ips_match.severity,
        blocked = ips_match.blocked,
        log_id = %log_id,
        "Decrypted traffic IPS match"
    );
    events::emit(events::Event::new(
        events::EventKind::DecryptedIpsMatch {
            peer: meta.peer,
            server: meta.server,
            sni: meta.sni.clone(),
            signature_name: ips_match.signature_name.clone(),
            severity: ips_match.severity.clone(),
            blocked: ips_match.blocked,
            direction,
            mode: meta.mode,
            log_id,
        },
    ));
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
            http_version = ctx.http_version.as_deref().unwrap_or(""),
            direction = ?direction,
            "Decrypted traffic classified"
        );
        events::emit(events::Event::new(
            events::EventKind::DecryptedTrafficClassified {
                peer: meta.peer,
                server: meta.server,
                sni: meta.sni.clone(),
                app_proto: proto.to_string(),
                http_version: ctx.http_version.clone(),
                direction,
                mode: meta.mode,
            },
        ));
    }
}

fn classification_changed(previous: &DpiContext, next: &DpiContext) -> bool {
    previous.app_proto != next.app_proto || previous.http_version != next.http_version
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::duplex;
    use tokio::time::{timeout, Duration};
    use tonic::async_trait;

    struct RecordingInspector {
        calls: Mutex<Vec<(Vec<u8>, bool)>>,
        disposition: InspectionDisposition,
    }

    impl RecordingInspector {
        fn new(disposition: InspectionDisposition) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                disposition,
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl DecryptedTrafficInspector for RecordingInspector {
        async fn inspect(
            &self,
            payload: &[u8],
            dpi_ctx: &DpiContext,
            _direction: Direction,
            _meta: &SessionMeta,
        ) -> crate::tls::decrypted_chain::InspectionDecision {
            self.calls
                .lock()
                .unwrap()
                .push((payload.to_vec(), dpi_ctx.decrypted));
            crate::tls::decrypted_chain::InspectionDecision {
                disposition: self.disposition,
                ctx: dpi_ctx.clone(),
                payload: payload.to_vec(),
            }
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
        let ips = Arc::new(crate::tls::decrypted_chain::NoopDecryptedInspector);
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
        let ips = Arc::new(RecordingInspector::new(InspectionDisposition::Drop));
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
        let ips = Arc::new(RecordingInspector::new(InspectionDisposition::Drop));
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
        let ips = Arc::new(RecordingInspector::new(InspectionDisposition::Forward));
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
    async fn eof_after_buffered_payload_closes_opposite_direction() {
        let relay = InspectionRelay::new(Arc::new(
            crate::tls::decrypted_chain::NoopDecryptedInspector,
        ));
        let meta = test_meta();

        let (client_tls, mut client_peer) = duplex(1024);
        let (server_tls, mut server_peer) = duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_tls);
        let (server_read, server_write) = tokio::io::split(server_tls);

        let relay_task = tokio::spawn(async move {
            relay
                .relay_bidirectional(
                    client_read,
                    server_write,
                    server_read,
                    client_write,
                    &meta,
                )
                .await
        });

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            timeout(Duration::from_secs(1), server_peer.read_to_end(&mut received))
                .await
                .expect("server did not observe EOF")
                .unwrap();
            received
        });

        client_peer.write_all(b"\n").await.unwrap();
        client_peer.shutdown().await.unwrap();

        let received = server_task.await.unwrap();
        assert_eq!(received, b"\n");

        let (up, down) = timeout(Duration::from_secs(1), relay_task)
            .await
            .expect("relay hung")
            .unwrap();
        assert_eq!(up, 1);
        assert_eq!(down, 0);
    }

    #[tokio::test]
    async fn noop_inspector_always_allows() {
        let inspector = crate::tls::decrypted_chain::NoopDecryptedInspector;
        let ctx = DpiContext::default();
        let decision = inspector
            .inspect(
                b"anything",
                &ctx,
                Direction::ClientToServer,
                &test_meta(),
            )
            .await;

        assert_eq!(decision.disposition, InspectionDisposition::Forward);
        assert_eq!(decision.payload, b"anything");
    }
}
