use std::sync::Arc;

use anyhow::Context;
use rustls::{ClientConfig, ServerConfig};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::extensions::{GeneralName, ParsedExtension};

// Parametry akceptacji TLS od klienta.
pub struct AcceptParams {
    pub tcp_stream: TcpStream,
    pub server_config: Arc<ServerConfig>,
}

// Parametry połączenia TLS do serwera docelowego.
pub struct ConnectParams {
    pub tcp_stream: TcpStream,
    pub client_config: Arc<ClientConfig>,
    pub server_name: String,
}

// Akceptuje połączenie TLS od klienta (firewall jako serwer).
pub async fn accept_client_tls(
    params: AcceptParams,
) -> anyhow::Result<ServerTlsStream<TcpStream>> {
    let acceptor = TlsAcceptor::from(params.server_config);
    acceptor
        .accept(params.tcp_stream)
        .await
        .context("TLS accept from client failed")
}

// Nawiązuje połączenie TLS do serwera docelowego (firewall jako klient).
pub async fn connect_to_server(
    params: ConnectParams,
) -> anyhow::Result<ClientTlsStream<TcpStream>> {
    let server_name = params
        .server_name
        .clone()
        .try_into()
        .context("Invalid server name for TLS connection")?;

    let connector = TlsConnector::from(params.client_config);
    connector
        .connect(server_name, params.tcp_stream)
        .await
        .context("TLS connect to server failed")
}

// Wyodrębnia DNS SAN z certyfikatu serwera po zakonczonym TLS handshake.
pub fn extract_peer_sans(stream: &ClientTlsStream<TcpStream>) -> Vec<String> {
    let Some(certs) = stream.get_ref().1.peer_certificates() else {
        return vec![];
    };
    let Some(first) = certs.first() else {
        return vec![];
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(first.as_ref()) else {
        return vec![];
    };

    let mut sans = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns) = name {
                    sans.push(dns.to_string());
                }
            }
        }
    }
    sans
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    fn make_localhost_cert() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            "localhost".to_string().try_into().unwrap(),
        )];
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn make_client_config_trusting(cert_pem: &str) -> Arc<ClientConfig> {
        use rustls::crypto::ring as rustls_ring;

        let certs = crate::tls::rustls_config::parse_cert_chain_pem(cert_pem).unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert).unwrap();
        }

        let config = ClientConfig::builder_with_provider(Arc::new(rustls_ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Arc::new(config)
    }

    #[tokio::test]
    async fn accept_client_tls_handshake() {
        let (cert_pem, key_pem) = make_localhost_cert();
        let server_config =
            crate::tls::rustls_config::build_server_config_from_pem(&cert_pem, &key_pem)
                .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();

        let client_config = make_client_config_trusting(&cert_pem);

        let server_handle = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            accept_client_tls(AcceptParams {
                tcp_stream,
                server_config,
            })
            .await
        });

        let client_tcp = TcpStream::connect(addr).await.unwrap();
        let server_name: rustls::pki_types::ServerName<'_> = "localhost".try_into().unwrap();
        let connector = TlsConnector::from(client_config);
        let client_result = connector.connect(server_name, client_tcp).await;

        assert!(client_result.is_ok());
        let server_result = server_handle.await.unwrap();
        assert!(server_result.is_ok());
    }

    #[tokio::test]
    async fn connect_to_server_handshake() {
        let (cert_pem, key_pem) = make_localhost_cert();

        let server_config =
            crate::tls::rustls_config::build_server_config_from_pem(&cert_pem, &key_pem)
                .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();

        let acceptor = TlsAcceptor::from(server_config);
        let server_handle = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await
        });

        let client_config = make_client_config_trusting(&cert_pem);

        let client_tcp = TcpStream::connect(addr).await.unwrap();
        let result = connect_to_server(ConnectParams {
            tcp_stream: client_tcp,
            client_config,
            server_name: "localhost".to_string(),
        })
        .await;

        assert!(result.is_ok());
        assert!(server_handle.await.unwrap().is_ok());
    }
}
