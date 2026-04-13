use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use rustls::{ProtocolVersion, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_util::sync::CancellationToken;

use crate::dpi::TlsAction;
use crate::dpi::parsers::tls::parse_tls_client_hello;
use crate::events;
use crate::events::{EchAction, EchOrigin, HandshakeStage};
use crate::tls::cert_forger::CertForger;
use crate::tls::decision_engine::TlsDecisionEngine;
use crate::tls::dual_session::{self, AcceptParams, ConnectParams};
use crate::tls::inspection_relay::{InspectionRelay, InspectionMode, IpsInspector, SessionMeta};
use crate::tls::original_dst;
use crate::tls::pinning_detector;
use crate::tls::rustls_config;

const SNI_PEEK_BUF_SIZE: usize = 4096;

// Konfiguracja proxy TLS (outbound MITM + inbound server key).
pub struct MitmProxyConfig {
    pub listen_addr: SocketAddr,
    pub cert_forger: Arc<CertForger>,
    pub untrust_forger: Arc<CertForger>,
    pub decision_engine: Arc<TlsDecisionEngine>,
    pub ips_inspector: Arc<dyn IpsInspector>,
    pub cancel: CancellationToken,
}

// Proxy TLS przechwytujące ruch przez iptables TPROXY/REDIRECT.
pub struct MitmProxy {
    listener: TcpListener,
    cert_forger: Arc<CertForger>,
    untrust_forger: Arc<CertForger>,
    decision_engine: Arc<TlsDecisionEngine>,
    inspection_relay: Arc<InspectionRelay>,
    cancel: CancellationToken,
}

impl MitmProxy {
    // Tworzy instancje proxy i binduje na podanym adresie.
    pub async fn bind(config: MitmProxyConfig) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .context("Nie udalo sie zbindowac listenera proxy MITM")?;

        tracing::info!(addr = %config.listen_addr, "TLS proxy listening");

        Ok(Self {
            listener,
            cert_forger: config.cert_forger,
            untrust_forger: config.untrust_forger,
            decision_engine: config.decision_engine,
            inspection_relay: Arc::new(InspectionRelay::new(config.ips_inspector)),
            cancel: config.cancel,
        })
    }

    // Glowna petla akceptujaca polaczenia.
    pub async fn serve(self) {
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    tracing::info!("TLS proxy shutting down");
                    return;
                }
                result = self.listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            let cert_forger = Arc::clone(&self.cert_forger);
                            let untrust_forger = Arc::clone(&self.untrust_forger);
                            let engine = Arc::clone(&self.decision_engine);
                            let relay = Arc::clone(&self.inspection_relay);

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    peer_addr,
                                    cert_forger,
                                    untrust_forger,
                                    engine,
                                    relay,
                                ).await {
                                    tracing::debug!(peer = %peer_addr, error = %e, "TLS proxy connection error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "TLS proxy accept error");
                        }
                    }
                }
            }
        }
    }
}

// Obsługuje przechwycone połączenie TLS (routing inbound vs outbound).
async fn handle_connection(
    client_tcp: TcpStream,
    peer_addr: SocketAddr,
    cert_forger: Arc<CertForger>,
    untrust_forger: Arc<CertForger>,
    engine: Arc<TlsDecisionEngine>,
    relay: Arc<InspectionRelay>,
) -> anyhow::Result<()> {
    let original_dst = original_dst::get_original_dst(&client_tcp)
        .context("Failed to read original destination address")?;

    let PeekedClientHello { sni, client_hello_version, ech_detected, looks_like_tls } =
        peek_client_hello(&client_tcp).await;

    if !looks_like_tls {
        tracing::debug!(peer = %peer_addr, dst = %original_dst, "Port 443 traffic is not TLS, using passthrough");
        return relay_tcp_passthrough(client_tcp, original_dst).await;
    }

    let action = engine.decide(
        sni.as_deref(),
        ech_detected,
        Some(original_dst.ip()),
        original_dst.port(),
        Some(peer_addr.ip()),
    );

    if ech_detected {
        let domain_hint = sni.clone().unwrap_or_else(|| original_dst.ip().to_string());
        events::emit(events::Event::new(events::EventKind::EchAttemptDetected {
            source_ip: Some(peer_addr.ip()),
            domain: domain_hint,
            origin: EchOrigin::ClientHelloOuterSni,
            action: if matches!(action, TlsAction::Block) {
                EchAction::Blocked
            } else {
                EchAction::Logged
            },
        }));
    }

    if let Some(entry) = engine.server_key_store().get_entry(original_dst) {
        if matches!(action, TlsAction::Bypass) {
            tracing::debug!(peer = %peer_addr, server = %original_dst, "Inbound TLS bypass");
            events::emit(events::Event::new(events::EventKind::InboundTlsBypassApplied {
                peer: peer_addr,
                server: original_dst,
                sni,
                tls_version: client_hello_version.clone(),
            }));
            return relay_tcp_passthrough(client_tcp, original_dst).await;
        }
        tracing::debug!(peer = %peer_addr, server = %original_dst, "Inbound TLS inspection");
        return handle_inbound_connection(
            client_tcp,
            peer_addr,
            original_dst,
            sni,
            client_hello_version,
            entry.common_name,
            entry.server_config,
            relay,
        )
        .await;
    }

    let domain = sni.clone().unwrap_or_else(|| original_dst.ip().to_string());

    match action {
        TlsAction::Bypass => {
            tracing::debug!(domain, "TLS bypass - relay without inspection");
            events::emit(events::Event::new(events::EventKind::TlsBypassApplied {
                peer: peer_addr,
                dst: original_dst,
                sni: sni.clone(),
                domain: domain.clone(),
                tls_version: client_hello_version.clone(),
            }));
            return relay_tcp_passthrough(client_tcp, original_dst).await;
        }
        TlsAction::Block => {
            tracing::info!(
                peer = %peer_addr,
                dst = %original_dst,
                sni = sni.as_deref().unwrap_or("none"),
                "TLS connection blocked before interception"
            );
            return Ok(());
        }
        TlsAction::Intercept | TlsAction::InterceptUntrust | TlsAction::None => {}
    }

    handle_outbound_connection(
        client_tcp, peer_addr, original_dst, sni, client_hello_version,
        cert_forger, untrust_forger, engine, relay,
    )
    .await
}

async fn handle_inbound_connection(
    client_tcp: TcpStream,
    peer_addr: SocketAddr,
    server_addr: SocketAddr,
    sni: Option<String>,
    client_hello_version: Option<String>,
    common_name: String,
    inbound_server_config: Arc<ServerConfig>,
    relay: Arc<InspectionRelay>,
) -> anyhow::Result<()> {
    events::emit(events::Event::new(
        events::EventKind::InboundTlsInterceptStarted {
            peer: peer_addr,
            server: server_addr,
            sni: sni.clone(),
            common_name,
            tls_version: client_hello_version.clone(),
        },
    ));

    let client_tls = match dual_session::accept_client_tls(AcceptParams {
        tcp_stream: client_tcp,
        server_config: inbound_server_config,
    })
    .await
    {
        Ok(tls) => tls,
        Err(e) => {
            events::emit(events::Event::new(events::EventKind::TlsHandshakeFailed {
                peer: peer_addr,
                dst: server_addr,
                sni: sni.clone(),
                tls_version: client_hello_version.clone(),
                stage: HandshakeStage::ClientHello,
                reason: describe_handshake_error(&e),
                mode: InspectionMode::Inbound,
            }));
            return Err(e.context("Inbound TLS accept from client failed"));
        }
    };

    let server_tcp = TcpStream::connect(server_addr)
        .await
        .context("Failed to connect to internal server")?;

    let re_encrypt_config = rustls_config::build_client_config_no_verify()
        .context("Failed to build re-encryption client config")?;

    let server_name = sni
        .clone()
        .unwrap_or_else(|| server_addr.ip().to_string());

    let server_tls = match dual_session::connect_to_server(ConnectParams {
        tcp_stream: server_tcp,
        client_config: re_encrypt_config,
        server_name: server_name.clone(),
    })
    .await
    {
        Ok(tls) => tls,
        Err(e) => {
            events::emit(events::Event::new(events::EventKind::TlsHandshakeFailed {
                peer: peer_addr,
                dst: server_addr,
                sni: sni.clone(),
                tls_version: negotiated_version_from_server(&client_tls).or_else(|| client_hello_version.clone()),
                stage: HandshakeStage::ServerHandshake,
                reason: describe_handshake_error(&e),
                mode: InspectionMode::Inbound,
            }));
            return Err(e.context("Inbound TLS connect to internal server failed"));
        }
    };

    let negotiated = negotiated_version_from_client(&server_tls)
        .or_else(|| negotiated_version_from_server(&client_tls))
        .or_else(|| client_hello_version.clone());

    let alpn = server_tls
        .get_ref()
        .1
        .alpn_protocol()
        .and_then(|a| String::from_utf8(a.to_vec()).ok());

    tracing::debug!(
        peer = %peer_addr,
        server = %server_addr,
        alpn = ?alpn,
        "Inbound TLS sessions established"
    );

    events::emit(events::Event::new(
        events::EventKind::InboundTlsHandshakeComplete {
            peer: peer_addr,
            server: server_addr,
            sni: sni.clone(),
            alpn,
            tls_version: negotiated,
        },
    ));

    // Inspekcja DPI/IPS na odszyfrowanym ruchu
    let (cr, cw) = tokio::io::split(client_tls);
    let (sr, sw) = tokio::io::split(server_tls);

    let meta = SessionMeta {
        peer: peer_addr,
        server: server_addr,
        sni: sni.clone(),
        mode: InspectionMode::Inbound,
    };

    let (bytes_up, bytes_down) = relay.relay_bidirectional(cr, sw, sr, cw, &meta).await;

    events::emit(events::Event::new(
        events::EventKind::InboundTlsSessionClosed {
            peer: peer_addr,
            server: server_addr,
            sni,
            bytes_up,
            bytes_down,
        },
    ));

    Ok(())
}

async fn handle_outbound_connection(
    client_tcp: TcpStream,
    peer_addr: SocketAddr,
    original_dst: SocketAddr,
    sni: Option<String>,
    client_hello_version: Option<String>,
    cert_forger: Arc<CertForger>,
    untrust_forger: Arc<CertForger>,
    engine: Arc<TlsDecisionEngine>,
    relay: Arc<InspectionRelay>,
) -> anyhow::Result<()> {
    let domain = sni.clone().unwrap_or_else(|| original_dst.ip().to_string());

    tracing::debug!(peer = %peer_addr, dst = %original_dst, "Outbound MITM intercepted");

    events::emit(events::Event::new(events::EventKind::TlsInterceptStarted {
        peer: peer_addr,
        dst: original_dst,
        sni: sni.clone(),
        tls_version: client_hello_version.clone(),
    }));

    let server_tcp = TcpStream::connect(original_dst)
        .await
        .context("Failed to connect to destination server")?;

    let (recording_config, trusted_flag) = rustls_config::build_client_config_recording()
        .context("Failed to build recording client config")?;

    let server_tls = match dual_session::connect_to_server(ConnectParams {
        tcp_stream: server_tcp,
        client_config: recording_config,
        server_name: domain.clone(),
    })
    .await
    {
        Ok(tls) => tls,
        Err(e) => {
            events::emit(events::Event::new(events::EventKind::TlsHandshakeFailed {
                peer: peer_addr,
                dst: original_dst,
                sni: sni.clone(),
                tls_version: client_hello_version.clone(),
                stage: HandshakeStage::ServerHandshake,
                reason: describe_handshake_error(&e),
                mode: InspectionMode::Outbound,
            }));
            return Err(e.context("TLS handshake with destination server failed"));
        }
    };

    let server_trusted = trusted_flag.load(std::sync::atomic::Ordering::Acquire);
    let extra_sans = dual_session::extract_peer_sans(&server_tls);

    let active_forger = if server_trusted { &cert_forger } else { &untrust_forger };

    let upstream_version = negotiated_version_from_client(&server_tls);

    if !server_trusted {
        tracing::warn!(
            peer = %peer_addr, dst = %original_dst, domain = %domain,
            "Server certificate untrusted, using Untrust CA"
        );
        events::emit(events::Event::new(events::EventKind::TlsUntrustedCertDetected {
            peer: peer_addr,
            dst: original_dst,
            sni: sni.clone(),
            domain: domain.clone(),
            tls_version: upstream_version.clone().or_else(|| client_hello_version.clone()),
        }));
    }

    let forged = active_forger
        .forge(&domain, &extra_sans)
        .context("Failed to forge certificate")?;

    let certified_key = forged
        .to_certified_key()
        .context("Failed to convert forged certificate")?;

    let forged_server_config = rustls_config::build_server_config_for_key(certified_key)
        .context("Failed to build server config")?;

    let client_tls = match dual_session::accept_client_tls(AcceptParams {
        tcp_stream: client_tcp,
        server_config: forged_server_config,
    })
    .await
    {
        Ok(tls) => tls,
        Err(e) => {
            let version_for_event = upstream_version.clone().or_else(|| client_hello_version.clone());
            if let Some(reason) = classify_pinning_failure(&e) {
                let activated = engine.report_pinning_failure(peer_addr.ip(), &domain, reason);
                if activated {
                    tracing::info!(peer = %peer_addr, domain = %domain, "Pinning auto-bypass activated");
                    events::emit(events::Event::new(events::EventKind::PinningAutoBypassActivated {
                        source_ip: peer_addr.ip(),
                        domain: domain.clone(),
                        reason: "handshake_failure".to_string(),
                    }));
                } else {
                    tracing::debug!(peer = %peer_addr, domain = %domain, "Pinning failure recorded");
                    events::emit(events::Event::new(events::EventKind::PinningFailureDetected {
                        peer: peer_addr,
                        dst: original_dst,
                        sni: domain.clone(),
                        tls_version: version_for_event.clone(),
                    }));
                }
            }
            events::emit(events::Event::new(events::EventKind::TlsHandshakeFailed {
                peer: peer_addr,
                dst: original_dst,
                sni: sni.clone(),
                tls_version: version_for_event,
                stage: HandshakeStage::ClientFinished,
                reason: describe_handshake_error(&e),
                mode: InspectionMode::Outbound,
            }));
            return Err(e).context("TLS accept from client failed");
        }
    };

    let negotiated = negotiated_version_from_server(&client_tls)
        .or(upstream_version)
        .or_else(|| client_hello_version.clone());

    let alpn = server_tls
        .get_ref()
        .1
        .alpn_protocol()
        .and_then(|a| String::from_utf8(a.to_vec()).ok());

    tracing::debug!(
        sni = sni.as_deref().unwrap_or("none"),
        alpn = ?alpn,
        replicated_sans = extra_sans.len(),
        trusted = server_trusted,
        "MITM TLS sessions established"
    );

    events::emit(events::Event::new(
        events::EventKind::TlsHandshakeComplete {
            peer: peer_addr,
            dst: original_dst,
            sni: sni.clone(),
            alpn,
            tls_version: negotiated,
        },
    ));

    let (client_read, client_write) = tokio::io::split(client_tls);
    let (server_read, server_write) = tokio::io::split(server_tls);

    let meta = SessionMeta {
        peer: peer_addr,
        server: original_dst,
        sni: sni.clone(),
        mode: InspectionMode::Outbound,
    };

    let (bytes_up, bytes_down) = relay.relay_bidirectional(
        client_read, server_write, server_read, client_write, &meta,
    ).await;

    events::emit(events::Event::new(events::EventKind::TlsSessionClosed {
        peer: peer_addr,
        dst: original_dst,
        sni,
        bytes_up,
        bytes_down,
    }));

    Ok(())
}

struct PeekedClientHello {
    sni: Option<String>,
    client_hello_version: Option<String>,
    ech_detected: bool,
    looks_like_tls: bool,
}

async fn peek_client_hello(stream: &TcpStream) -> PeekedClientHello {
    let mut buf = [0u8; SNI_PEEK_BUF_SIZE];
    let Ok(n) = stream.peek(&mut buf).await else {
        return PeekedClientHello {
            sni: None,
            client_hello_version: None,
            ech_detected: false,
            looks_like_tls: false,
        };
    };
    let looks_like_tls = looks_like_tls_client_hello_prefix(&buf[..n]);
    let Some(result) = parse_tls_client_hello(&buf[..n]) else {
        return PeekedClientHello {
            sni: None,
            client_hello_version: None,
            ech_detected: false,
            looks_like_tls,
        };
    };
    PeekedClientHello {
        sni: result.sni,
        client_hello_version: Some(events::format_tls_version(result.version)),
        ech_detected: result.ech_detected,
        looks_like_tls: true,
    }
}

fn looks_like_tls_client_hello_prefix(buf: &[u8]) -> bool {
    buf.len() >= 3 && buf[0] == 0x16 && buf[1] == 0x03 && (1..=4).contains(&buf[2])
}

fn negotiated_version_from_client(stream: &ClientTlsStream<TcpStream>) -> Option<String> {
    stream.get_ref().1.protocol_version().map(protocol_version_string)
}

fn negotiated_version_from_server(stream: &ServerTlsStream<TcpStream>) -> Option<String> {
    stream.get_ref().1.protocol_version().map(protocol_version_string)
}

fn protocol_version_string(version: ProtocolVersion) -> String {
    events::format_tls_version(u16::from(version))
}

fn describe_handshake_error(err: &anyhow::Error) -> String {
    if let Some(rustls_err) = err.downcast_ref::<rustls::Error>() {
        return format!("rustls: {rustls_err}");
    }
    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        if let Some(inner) = io_err.get_ref() {
            if let Some(rustls_err) = inner.downcast_ref::<rustls::Error>() {
                return format!("rustls: {rustls_err}");
            }
        }
        return format!("io: {}", io_err.kind());
    }
    err.to_string()
}

/// Klasyfikuje błąd TLS jako potencjalny sygnał certificate pinningu.
fn classify_pinning_failure(err: &anyhow::Error) -> Option<pinning_detector::PinningReason> {
    use crate::tls::pinning_detector::PinningReason;

    if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        if io_err.kind() == std::io::ErrorKind::ConnectionReset {
            return Some(PinningReason::TcpReset);
        }
        if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
            return Some(PinningReason::ConnectionClosedNoData);
        }
    }

    let msg = err.to_string();
    for alert in ["bad_certificate", "certificate_unknown", "unknown_ca", "certificate_required"] {
        if msg.contains(alert) {
            return Some(PinningReason::TlsAlert { alert_description: alert.to_string() });
        }
    }

    None
}

// Przekazuje ruch TCP bez inspekcji TLS.
async fn relay_tcp_passthrough(
    mut client: TcpStream,
    original_dst: SocketAddr,
) -> anyhow::Result<()> {
    let mut server = TcpStream::connect(original_dst)
        .await
        .context("Nie udalo sie polaczyc dla TCP passthrough")?;

    tokio::io::copy_bidirectional(&mut client, &mut server)
        .await
        .context("Blad relay TCP passthrough")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_buf_size_enough_for_client_hello() {
        assert!(SNI_PEEK_BUF_SIZE >= 512);
    }

    #[test]
    fn tls_prefix_heuristic_accepts_handshake_record() {
        assert!(looks_like_tls_client_hello_prefix(&[0x16, 0x03, 0x03]));
    }

    #[test]
    fn tls_prefix_heuristic_rejects_plaintext() {
        assert!(!looks_like_tls_client_hello_prefix(b"GET /"));
    }
}
