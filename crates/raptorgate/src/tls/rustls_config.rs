use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring as rustls_ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig};

pub fn default_alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

pub fn sanitize_alpn_protocols(protocols: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut sanitized = Vec::with_capacity(protocols.len());
    for protocol in protocols {
        if protocol.is_empty() || sanitized.iter().any(|existing| existing == protocol) {
            continue;
        }
        sanitized.push(protocol.clone());
    }
    sanitized
}

fn resolve_alpn_protocols(protocols: Option<&[Vec<u8>]>) -> Vec<Vec<u8>> {
    match protocols {
        Some(protocols) => sanitize_alpn_protocols(protocols),
        None => default_alpn_protocols(),
    }
}

pub fn build_certified_key_from_pem(
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<Arc<CertifiedKey>> {
    let certs = parse_cert_chain_pem(cert_pem)?;
    let key = parse_private_key_pem(key_pem)?;

    let signing_key = rustls_ring::sign::any_supported_type(&key)
        .context("Unsupported private key type")?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Konfiguracja serwera TLS ze statycznym certyfikatem PEM dla trybu inbound
pub fn build_server_config_from_pem(
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<Arc<ServerConfig>> {
    build_server_config_from_pem_with_alpn(cert_pem, key_pem, &default_alpn_protocols())
}

pub fn build_server_config_from_pem_with_alpn(
    cert_pem: &str,
    key_pem: &str,
    alpn_protocols: &[Vec<u8>],
) -> anyhow::Result<Arc<ServerConfig>> {
    let certified = build_certified_key_from_pem(cert_pem, key_pem)?;
    build_server_config_for_key_with_alpn(certified, alpn_protocols)
}

pub fn parse_cert_chain_pem(pem: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate chain PEM")?;

    anyhow::ensure!(!certs.is_empty(), "No certificates found in PEM data");
    Ok(certs)
}

pub fn parse_private_key_pem(pem: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .context("Failed to parse private key PEM")?
        .context("No private key found in PEM data")
}

/// Klient TLS do re-encryption w trybie inbound
pub fn build_client_config_no_verify() -> anyhow::Result<Arc<ClientConfig>> {
    build_client_config_no_verify_with_alpn(&default_alpn_protocols())
}

pub fn build_client_config_no_verify_with_alpn(
    alpn_protocols: &[Vec<u8>],
) -> anyhow::Result<Arc<ClientConfig>> {
    let mut config: ClientConfig = ClientConfig::builder_with_provider(Arc::new(rustls_ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("Failed to set TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    config.alpn_protocols = resolve_alpn_protocols(Some(alpn_protocols));

    Ok(Arc::new(config))
}

/// Konfiguracja serwera TLS ze sfałszowanym certyfikatem dla outbound MITM
pub fn build_server_config_for_key(key: Arc<CertifiedKey>) -> anyhow::Result<Arc<ServerConfig>> {
    build_server_config_for_key_with_alpn(key, &default_alpn_protocols())
}

pub fn build_server_config_for_key_with_alpn(
    key: Arc<CertifiedKey>,
    alpn_protocols: &[Vec<u8>],
) -> anyhow::Result<Arc<ServerConfig>> {
    let resolver = SingleCertResolver(key);

    let mut config = ServerConfig::builder_with_provider(Arc::new(rustls_ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("Failed to set TLS protocol versions")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    config.alpn_protocols = resolve_alpn_protocols(Some(alpn_protocols));

    Ok(Arc::new(config))
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls_ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls_ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls_ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// Weryfikator rejestrujący wynik walidacji bez blokowania handshake'a.
#[derive(Debug)]
pub struct RecordingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    trusted: Arc<AtomicBool>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = self.inner.verify_server_cert(
            end_entity, intermediates, server_name, ocsp_response, now,
        );
        self.trusted.store(result.is_ok(), Ordering::Release);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss,
            &rustls_ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss,
            &rustls_ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls_ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// Klient TLS rejestrujący zaufanie certyfikatu serwera (do Forward Untrust CA).
pub fn build_client_config_recording() -> anyhow::Result<(Arc<ClientConfig>, Arc<AtomicBool>)> {
    build_client_config_recording_with_alpn(&default_alpn_protocols())
}

pub fn build_client_config_recording_with_alpn(
    alpn_protocols: &[Vec<u8>],
) -> anyhow::Result<(Arc<ClientConfig>, Arc<AtomicBool>)> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = rustls_ring::default_provider();
    let inner = WebPkiServerVerifier::builder_with_provider(
        Arc::new(root_store),
        Arc::new(provider),
    )
    .build()
    .context("Failed to build WebPKI server verifier")?;

    let trusted = Arc::new(AtomicBool::new(true));
    let verifier = Arc::new(RecordingVerifier {
        inner,
        trusted: Arc::clone(&trusted),
    });

    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls_ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("Failed to set TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    config.alpn_protocols = resolve_alpn_protocols(Some(alpn_protocols));

    Ok((Arc::new(config), trusted))
}

#[derive(Debug)]
struct SingleCertResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair};

    fn make_self_signed() -> (String, String) {
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

    #[test]
    fn server_config_from_pem_builds_successfully() {
        let (cert_pem, key_pem) = make_self_signed();
        let config = build_server_config_from_pem(&cert_pem, &key_pem);
        assert!(config.is_ok());
    }

    #[test]
    fn server_config_from_pem_respects_custom_alpn() {
        let (cert_pem, key_pem) = make_self_signed();
        let config = build_server_config_from_pem_with_alpn(&cert_pem, &key_pem, &[b"http/1.1".to_vec()]).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn server_config_for_key_builds_successfully() {
        let (cert_pem, key_pem) = make_self_signed();
        let certified = build_certified_key_from_pem(&cert_pem, &key_pem).unwrap();

        let config = build_server_config_for_key(certified).unwrap();
        assert_eq!(config.alpn_protocols, default_alpn_protocols());
    }

    #[test]
    fn sanitize_alpn_protocols_removes_duplicates_and_empty() {
        let protocols = sanitize_alpn_protocols(&[
            b"h2".to_vec(),
            Vec::new(),
            b"http/1.1".to_vec(),
            b"h2".to_vec(),
        ]);

        assert_eq!(protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn parse_cert_chain_returns_single_cert() {
        let (cert_pem, _) = make_self_signed();
        let certs = parse_cert_chain_pem(&cert_pem).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn parse_cert_chain_returns_error_on_empty() {
        let result = parse_cert_chain_pem("not a cert");
        assert!(result.is_err());
    }

    #[test]
    fn parse_private_key_succeeds() {
        let (_, key_pem) = make_self_signed();
        let key = parse_private_key_pem(&key_pem);
        assert!(key.is_ok());
    }

    #[test]
    fn parse_private_key_fails_on_garbage() {
        let result = parse_private_key_pem("not a key");
        assert!(result.is_err());
    }

    #[test]
    fn client_config_recording_builds_successfully() {
        let (config, _trusted) = build_client_config_recording().unwrap();
        assert_eq!(config.alpn_protocols, default_alpn_protocols());
    }

    #[test]
    fn client_config_recording_respects_custom_alpn() {
        let (config, _trusted) = build_client_config_recording_with_alpn(&[b"http/1.1".to_vec()]).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
