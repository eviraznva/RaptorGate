use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use rustls::{ClientConfig, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::dpi::parsers::tls::parse_tls_client_hello;
use crate::events;
use crate::tls::dual_session::{self, AcceptParams, ConnectParams};
use crate::tls::original_dst;

const SNI_PEEK_BUF_SIZE: usize = 4096;

// Konfiguracja proxy MITM TLS.
pub struct MitmProxyConfig {
    pub listen_addr: SocketAddr,
    pub server_config: Arc<ServerConfig>,
    pub client_config: Arc<ClientConfig>,
    pub bypass_domains: Vec<String>,
    pub cancel: CancellationToken,
}

// Proxy MITM przechwytujace ruch TLS przez iptables TPROXY/REDIRECT.
pub struct MitmProxy {
    listener: TcpListener,
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    bypass_domains: Arc<Vec<String>>,
    cancel: CancellationToken,
}

impl MitmProxy {
    // Tworzy nowa instancje proxy i binduje na podanym adresie.
    pub async fn bind(config: MitmProxyConfig) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(config.listen_addr)
            .await
            .context("Nie udalo sie zbindowac listenera proxy MITM")?;

        tracing::info!(addr = %config.listen_addr, "MITM proxy listening");

        Ok(Self {
            listener,
            server_config: config.server_config,
            client_config: config.client_config,
            bypass_domains: Arc::new(config.bypass_domains),
            cancel: config.cancel,
        })
    }

    // Glowna petla akceptujaca polaczenia.
    pub async fn serve(self) {
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    tracing::info!("MITM proxy shutting down");
                    return;
                }
                result = self.listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            let server_config = Arc::clone(&self.server_config);
                            let client_config = Arc::clone(&self.client_config);
                            let bypass = Arc::clone(&self.bypass_domains);

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    peer_addr,
                                    server_config,
                                    client_config,
                                    bypass,
                                ).await {
                                    tracing::debug!(peer = %peer_addr, error = %e, "MITM connection error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "MITM accept error");
                        }
                    }
                }
            }
        }
    }
}

// Obsluguje pojedyncze przechwycone polaczenie TLS.
async fn handle_connection(
    client_tcp: TcpStream,
    peer_addr: SocketAddr,
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    bypass_domains: Arc<Vec<String>>,
) -> anyhow::Result<()> {
    let original_dst = original_dst::get_original_dst(&client_tcp)
        .context("Nie udalo sie odczytac oryginalnego adresu docelowego")?;

    tracing::debug!(peer = %peer_addr, dst = %original_dst, "MITM intercepted connection");

    let sni = peek_sni(&client_tcp).await;
    let domain = sni.as_deref().unwrap_or("unknown");

    if is_bypassed(domain, &bypass_domains) {
        tracing::debug!(domain, "TLS bypass - relay bez inspekcji");
        return relay_tcp_passthrough(client_tcp, original_dst).await;
    }

    events::emit(events::Event::new(events::EventKind::TlsInterceptStarted {
        peer: peer_addr,
        dst: original_dst,
        sni: sni.clone(),
    }));

    let server_tcp = TcpStream::connect(original_dst)
        .await
        .context("Nie udalo sie polaczyc z serwerem docelowym")?;

    let server_name = sni.clone().unwrap_or_else(|| original_dst.ip().to_string());

    let dual = dual_session::establish_dual_session(
        AcceptParams {
            tcp_stream: client_tcp,
            server_config,
        },
        ConnectParams {
            tcp_stream: server_tcp,
            client_config,
            server_name: server_name.clone(),
        },
    )
    .await
    .context("Nie udalo sie zestawic podwojnej sesji TLS")?;

    tracing::debug!(
        domain,
        alpn = ?dual.negotiated_alpn.as_ref().map(|a| String::from_utf8_lossy(a)),
        "MITM TLS sessions established"
    );

    events::emit(events::Event::new(events::EventKind::TlsHandshakeComplete {
        peer: peer_addr,
        dst: original_dst,
        sni: sni.clone(),
        alpn: dual.negotiated_alpn.clone().and_then(|a| String::from_utf8(a).ok()),
    }));

    let (mut client_read, mut client_write) = tokio::io::split(dual.client_stream);
    let (mut server_read, mut server_write) = tokio::io::split(dual.server_stream);

    let c2s = tokio::io::copy(&mut client_read, &mut server_write);
    let s2c = tokio::io::copy(&mut server_read, &mut client_write);

    let (c2s_result, s2c_result) = tokio::join!(c2s, s2c);

    let bytes_up = c2s_result.unwrap_or(0);
    let bytes_down = s2c_result.unwrap_or(0);

    events::emit(events::Event::new(events::EventKind::TlsSessionClosed {
        peer: peer_addr,
        dst: original_dst,
        sni,
        bytes_up,
        bytes_down,
    }));

    Ok(())
}

// Wyodrebnia SNI z ClientHello przez peek na strumieniu TCP (bez konsumowania danych).
async fn peek_sni(stream: &TcpStream) -> Option<String> {
    let mut buf = [0u8; SNI_PEEK_BUF_SIZE];
    let n = stream.peek(&mut buf).await.ok()?;
    let result = parse_tls_client_hello(&buf[..n])?;
    result.sni
}

// Sprawdza czy domena jest na liscie bypass (pomijania inspekcji TLS).
fn is_bypassed(domain: &str, bypass_list: &[String]) -> bool {
    let domain_lower = domain.to_lowercase();
    bypass_list.iter().any(|suffix| {
        domain_lower == *suffix || domain_lower.ends_with(&format!(".{suffix}"))
    })
}

// Przekazuje ruch TCP bez inspekcji TLS (tryb passthrough).
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
    fn bypass_exact_match() {
        let list = vec!["example.com".to_string()];
        assert!(is_bypassed("example.com", &list));
    }

    #[test]
    fn bypass_subdomain_match() {
        let list = vec!["example.com".to_string()];
        assert!(is_bypassed("www.example.com", &list));
        assert!(is_bypassed("deep.sub.example.com", &list));
    }

    #[test]
    fn bypass_no_match() {
        let list = vec!["example.com".to_string()];
        assert!(!is_bypassed("notexample.com", &list));
        assert!(!is_bypassed("example.org", &list));
    }

    #[test]
    fn bypass_case_insensitive() {
        let list = vec!["example.com".to_string()];
        assert!(is_bypassed("EXAMPLE.COM", &list));
        assert!(is_bypassed("Www.Example.COM", &list));
    }

    #[test]
    fn bypass_empty_list() {
        let list: Vec<String> = vec![];
        assert!(!is_bypassed("example.com", &list));
    }

    #[test]
    fn bypass_multiple_entries() {
        let list = vec!["bank.com".to_string(), "gov.pl".to_string()];
        assert!(is_bypassed("www.bank.com", &list));
        assert!(is_bypassed("portal.gov.pl", &list));
        assert!(!is_bypassed("example.com", &list));
    }
}
