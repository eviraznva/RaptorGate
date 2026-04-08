use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use rustls::{ClientConfig, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::dpi::parsers::tls::parse_tls_client_hello;
use crate::events;
use crate::tls::cert_forger::CertForger;
use crate::tls::decision_engine::TlsDecisionEngine;
use crate::tls::dual_session::{self, AcceptParams, ConnectParams};
use crate::tls::inspection_relay::{InspectionRelay, InspectionMode, IpsInspector, SessionMeta};
use crate::tls::original_dst;
use crate::tls::rustls_config;

const SNI_PEEK_BUF_SIZE: usize = 4096;

// Konfiguracja proxy TLS (outbound MITM + inbound server key).
pub struct MitmProxyConfig {
    pub listen_addr: SocketAddr,
    pub client_config: Arc<ClientConfig>,
    pub cert_forger: Arc<CertForger>,
    pub untrust_forger: Arc<CertForger>,
    pub decision_engine: Arc<TlsDecisionEngine>,
    pub ips_inspector: Arc<dyn IpsInspector>,
    pub cancel: CancellationToken,
}

// Proxy TLS przechwytujące ruch przez iptables TPROXY/REDIRECT.
pub struct MitmProxy {
    listener: TcpListener,
    client_config: Arc<ClientConfig>,
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
            client_config: config.client_config,
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
                            let client_config = Arc::clone(&self.client_config);
                            let cert_forger = Arc::clone(&self.cert_forger);
                            let untrust_forger = Arc::clone(&self.untrust_forger);
                            let engine = Arc::clone(&self.decision_engine);
                            let relay = Arc::clone(&self.inspection_relay);

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    peer_addr,
                                    client_config,
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
    client_config: Arc<ClientConfig>,
    cert_forger: Arc<CertForger>,
    untrust_forger: Arc<CertForger>,
    engine: Arc<TlsDecisionEngine>,
    relay: Arc<InspectionRelay>,
) -> anyhow::Result<()> {
    let original_dst = original_dst::get_original_dst(&client_tcp)
        .context("Failed to read original destination address")?;

    let sni = peek_sni(&client_tcp).await;

    if let Some(entry) = engine.server_key_store().get_entry(original_dst) {
        if entry.bypass {
            tracing::debug!(peer = %peer_addr, server = %original_dst, "Inbound TLS bypass");
            events::emit(events::Event::new(events::EventKind::InboundTlsBypassApplied {
                peer: peer_addr,
                server: original_dst,
                sni,
            }));
            return relay_tcp_passthrough(client_tcp, original_dst).await;
        }
        tracing::debug!(peer = %peer_addr, server = %original_dst, "Inbound TLS inspection");
        return handle_inbound_connection(
            client_tcp, peer_addr, original_dst, sni, entry.server_config, relay,
        )
        .await;
    }

    let domain = sni.as_deref().unwrap_or("unknown");

    if engine.is_domain_bypassed(domain) {
        tracing::debug!(domain, "TLS bypass - relay without inspection");
        events::emit(events::Event::new(events::EventKind::TlsBypassApplied {
            peer: peer_addr,
            dst: original_dst,
            sni: sni.clone(),
            domain: domain.to_string(),
        }));
        return relay_tcp_passthrough(client_tcp, original_dst).await;
    }

    handle_outbound_connection(
        client_tcp, peer_addr, original_dst, sni,
        client_config, cert_forger, untrust_forger, relay,
    )
    .await
}

// Obsługuje połączenie inbound (firewall terminuje TLS prawdziwym certem serwera).
async fn handle_inbound_connection(
    client_tcp: TcpStream,
    peer_addr: SocketAddr,
    server_addr: SocketAddr,
    sni: Option<String>,
    inbound_server_config: Arc<ServerConfig>,
    relay: Arc<InspectionRelay>,
) -> anyhow::Result<()> {
    events::emit(events::Event::new(
        events::EventKind::InboundTlsInterceptStarted {
            peer: peer_addr,
            server: server_addr,
            sni: sni.clone(),
            common_name: String::new(),
        },
    ));

    // Terminacja TLS od klienta prawdziwym certyfikatem serwera
    let client_tls = dual_session::accept_client_tls(AcceptParams {
        tcp_stream: client_tcp,
        server_config: inbound_server_config,
    })
    .await
    .context("Inbound TLS accept from client failed")?;

    // Re-encryption: nowe polaczenie TLS do serwera wewnetrznego.
    // Uzywamy no-verify bo admin explicite skonfigurowal ten serwer.
    let server_tcp = TcpStream::connect(server_addr)
        .await
        .context("Failed to connect to internal server")?;

    let re_encrypt_config = rustls_config::build_client_config_no_verify()
        .context("Failed to build re-encryption client config")?;

    let server_name = sni
        .clone()
        .unwrap_or_else(|| server_addr.ip().to_string());

    let server_tls = dual_session::connect_to_server(ConnectParams {
        tcp_stream: server_tcp,
        client_config: re_encrypt_config,
        server_name: server_name.clone(),
    })
    .await
    .context("Inbound TLS connect to internal server failed")?;

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

// Obsluguje polaczenie outbound MITM (sfałszowany certyfikat z replikacja SAN).
async fn handle_outbound_connection(
    client_tcp: TcpStream,
    peer_addr: SocketAddr,
    original_dst: SocketAddr,
    sni: Option<String>,
    client_config: Arc<ClientConfig>,
    cert_forger: Arc<CertForger>,
    untrust_forger: Arc<CertForger>,
    relay: Arc<InspectionRelay>,
) -> anyhow::Result<()> {
    let domain = sni.clone().unwrap_or_else(|| original_dst.ip().to_string());

    tracing::debug!(peer = %peer_addr, dst = %original_dst, "Outbound MITM intercepted");

    events::emit(events::Event::new(events::EventKind::TlsInterceptStarted {
        peer: peer_addr,
        dst: original_dst,
        sni: sni.clone(),
    }));

    let server_tcp = TcpStream::connect(original_dst)
        .await
        .context("Failed to connect to destination server")?;

    let (recording_config, trusted_flag) = rustls_config::build_client_config_recording()
        .context("Failed to build recording client config")?;

    let server_tls = dual_session::connect_to_server(ConnectParams {
        tcp_stream: server_tcp,
        client_config: recording_config,
        server_name: domain.clone(),
    })
    .await
    .context("TLS handshake with destination server failed")?;

    let server_trusted = trusted_flag.load(std::sync::atomic::Ordering::Acquire);
    let extra_sans = dual_session::extract_peer_sans(&server_tls);

    let active_forger = if server_trusted { &cert_forger } else { &untrust_forger };

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

    let client_tls = dual_session::accept_client_tls(AcceptParams {
        tcp_stream: client_tcp,
        server_config: forged_server_config,
    })
    .await
    .context("TLS accept from client failed")?;

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

// Wyodrebnia SNI z ClientHello przez peek (bez konsumowania danych).
async fn peek_sni(stream: &TcpStream) -> Option<String> {
    let mut buf = [0u8; SNI_PEEK_BUF_SIZE];
    let n = stream.peek(&mut buf).await.ok()?;
    let result = parse_tls_client_hello(&buf[..n])?;
    result.sni
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
}
