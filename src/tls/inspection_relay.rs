use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

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

/// Relay jednego kierunku: buforuje poczatek, klasyfikuje, inspekcjonuje, potem passthrough.
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
    let mut total_bytes: u64 = 0;
    let mut inspect_buf = Vec::with_capacity(INSPECT_BUF_CAP);
    let mut chunks_seen: u8 = 0;
    let mut classified = false;
    let mut buf = [0u8; CHUNK_SIZE];

    // Faza inspekcji: buforuj i analizuj pierwsze chunki
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => return total_bytes,
            Ok(n) => n,
            Err(_) => return total_bytes,
        };

        if writer.write_all(&buf[..n]).await.is_err() {
            return total_bytes + n as u64;
        }
        total_bytes += n as u64;

        let remaining = INSPECT_BUF_CAP.saturating_sub(inspect_buf.len());
        let to_copy = n.min(remaining);
        inspect_buf.extend_from_slice(&buf[..to_copy]);
        chunks_seen += 1;

        if let Some(ctx) = DpiClassifier::try_classify(&inspect_buf) {
            let mut ctx = ctx;
            ctx.decrypted = true;

            if let Err(blocked) = handle_verdict(ips, &inspect_buf, &ctx, meta, direction) {
                if blocked {
                    return total_bytes;
                }
            }

            emit_classification_event(meta, &ctx, direction);
            classified = true;
            break;
        }

        if chunks_seen >= MAX_INSPECT_CHUNKS || inspect_buf.len() >= INSPECT_BUF_CAP {
            let ctx = DpiContext {
                app_proto: Some(AppProto::Unknown),
                decrypted: true,
                ..Default::default()
            };
            emit_classification_event(meta, &ctx, direction);
            classified = true;
            break;
        }
    }

    drop(inspect_buf);

    if !classified {
        return total_bytes;
    }

    // Faza passthrough: bezposredni copy bez buforowania
    match tokio::io::copy(&mut reader, &mut writer).await {
        Ok(n) => total_bytes + n,
        Err(_) => total_bytes,
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
