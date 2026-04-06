use std::sync::Arc;

use anyhow::Context;
use rustls::{ClientConfig, ServerConfig};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::extensions::{GeneralName, ParsedExtension};

// Para sesji TLS: klient↔firewall i firewall↔serwer docelowy.
pub struct DualTlsSession {
    pub client_stream: ServerTlsStream<TcpStream>,
    pub server_stream: ClientTlsStream<TcpStream>,
    pub negotiated_alpn: Option<Vec<u8>>,
}

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

// Zestawia obie sesje TLS równolegle.
pub async fn establish_dual_session(
    accept: AcceptParams,
    connect: ConnectParams,
) -> anyhow::Result<DualTlsSession> {
    let (client_result, server_result) =
        tokio::join!(accept_client_tls(accept), connect_to_server(connect));

    let client_stream = client_result?;
    let server_stream = server_result?;

    let negotiated_alpn = server_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| p.to_vec());

    Ok(DualTlsSession {
        client_stream,
        server_stream,
        negotiated_alpn,
    })
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
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    fn make_ca() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn make_server_config() -> Arc<ServerConfig> {
        let (ca_cert_pem, ca_key_pem) = make_ca();
        let forger = Arc::new(
            crate::tls::CertForger::new(&ca_cert_pem, &ca_key_pem, 10).unwrap(),
        );
        let resolver = Arc::new(
            crate::tls::server_cert_resolver::SniForgingResolver::new(forger),
        );
        crate::tls::rustls_config::build_server_config(resolver).unwrap()
    }

    fn make_client_config_trusting_ca(ca_cert_pem: &str) -> Arc<ClientConfig> {
        use rustls::crypto::ring as rustls_ring;

        let certs = crate::tls::rustls_config::parse_cert_chain_pem(ca_cert_pem).unwrap();

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
        let (ca_cert_pem, ca_key_pem) = make_ca();
        let forger = Arc::new(
            crate::tls::CertForger::new(&ca_cert_pem, &ca_key_pem, 10).unwrap(),
        );
        let resolver = Arc::new(
            crate::tls::server_cert_resolver::SniForgingResolver::new(forger),
        );
        let server_config =
            crate::tls::rustls_config::build_server_config(resolver).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();

        let client_config = make_client_config_trusting_ca(&ca_cert_pem);

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

        let server_config =
            crate::tls::rustls_config::build_server_config_from_pem(
                &cert.pem(),
                &key.serialize_pem(),
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();

        let acceptor = TlsAcceptor::from(server_config);
        let server_handle = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await
        });

        let mut root_store = rustls::RootCertStore::empty();
        let certs = crate::tls::rustls_config::parse_cert_chain_pem(&cert.pem()).unwrap();
        for c in certs {
            root_store.add(c).unwrap();
        }
        let client_config = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
        );

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

    #[tokio::test]
    async fn dual_session_establishes_both_sides() {
        let (ca_cert_pem, ca_key_pem) = make_ca();
        let forger = Arc::new(
            crate::tls::CertForger::new(&ca_cert_pem, &ca_key_pem, 10).unwrap(),
        );
        let resolver = Arc::new(
            crate::tls::server_cert_resolver::SniForgingResolver::new(Arc::clone(&forger)),
        );
        let mitm_server_config =
            crate::tls::rustls_config::build_server_config(resolver).unwrap();

        let real_key = KeyPair::generate().unwrap();
        let mut real_params = CertificateParams::default();
        real_params.is_ca = IsCa::NoCa;
        real_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        real_params.subject_alt_names = vec![rcgen::SanType::DnsName(
            "localhost".to_string().try_into().unwrap(),
        )];
        let real_cert = real_params.self_signed(&real_key).unwrap();

        let real_server_config =
            crate::tls::rustls_config::build_server_config_from_pem(
                &real_cert.pem(),
                &real_key.serialize_pem(),
            )
            .unwrap();

        let real_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let real_addr: SocketAddr = real_listener.local_addr().unwrap();

        let real_acceptor = TlsAcceptor::from(real_server_config);
        let real_server_handle = tokio::spawn(async move {
            let (tcp, _) = real_listener.accept().await.unwrap();
            real_acceptor.accept(tcp).await
        });

        let mitm_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mitm_addr: SocketAddr = mitm_listener.local_addr().unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        let real_certs =
            crate::tls::rustls_config::parse_cert_chain_pem(&real_cert.pem()).unwrap();
        for c in real_certs {
            root_store.add(c).unwrap();
        }
        let fw_client_config = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
        );

        let mitm_handle = tokio::spawn(async move {
            let (mitm_tcp, _) = mitm_listener.accept().await.unwrap();
            let fw_to_server_tcp = TcpStream::connect(real_addr).await.unwrap();

            establish_dual_session(
                AcceptParams {
                    tcp_stream: mitm_tcp,
                    server_config: mitm_server_config,
                },
                ConnectParams {
                    tcp_stream: fw_to_server_tcp,
                    client_config: fw_client_config,
                    server_name: "localhost".to_string(),
                },
            )
            .await
        });

        let client_config = make_client_config_trusting_ca(&ca_cert_pem);
        let client_tcp = TcpStream::connect(mitm_addr).await.unwrap();
        let server_name: rustls::pki_types::ServerName<'_> = "localhost".try_into().unwrap();
        let connector = TlsConnector::from(client_config);
        let client_result = connector.connect(server_name, client_tcp).await;

        assert!(client_result.is_ok());

        let dual = mitm_handle.await.unwrap();
        assert!(dual.is_ok());

        assert!(real_server_handle.await.unwrap().is_ok());
    }
}
