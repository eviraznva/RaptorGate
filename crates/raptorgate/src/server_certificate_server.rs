use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

use crate::proto::services::firewall_server_certificate_service_server::{
    FirewallServerCertificateService, FirewallServerCertificateServiceServer,
};
use crate::proto::services::{
    UploadServerCertificateRequest, UploadServerCertificateResponse,
};
use crate::tls::ca_manager::compute_fingerprint;
use crate::tls::rustls_config::parse_cert_chain_pem;
use crate::tls::ServerKeyStore;

pub struct ServerCertificateServer {
    handler: ServerCertificateHandler,
    socket_path: String,
    shutdown: CancellationToken,
}

impl ServerCertificateServer {
    pub fn new(
        handler: ServerCertificateHandler,
        socket_path: impl Into<String>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            handler,
            socket_path: socket_path.into(),
            shutdown,
        }
    }

    pub async fn serve(self) {
        if let Err(e) = prepare_socket(&self.socket_path) {
            tracing::error!(socket = self.socket_path, error = %e, "failed to prepare server-cert socket");
            return;
        }

        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(socket = self.socket_path, error = %e, "failed to bind server-cert socket");
                return;
            }
        };

        tracing::info!(socket = self.socket_path, "ServerCertificateServer listening");
        let incoming = UnixListenerStream::new(listener);

        if let Err(e) = tonic::transport::Server::builder()
            .add_service(FirewallServerCertificateServiceServer::new(self.handler))
            .serve_with_incoming_shutdown(incoming, self.shutdown.cancelled())
            .await
        {
            tracing::error!(error = %e, "ServerCertificateServer error");
        }

        cleanup_socket(&self.socket_path);
    }
}

pub struct ServerCertificateHandler {
    pub server_key_store: Arc<ServerKeyStore>,
}

#[tonic::async_trait]
impl FirewallServerCertificateService for ServerCertificateHandler {
    async fn upload_server_certificate(
        &self,
        request: Request<UploadServerCertificateRequest>,
    ) -> Result<Response<UploadServerCertificateResponse>, Status> {
        let req = request.into_inner();

        let addr = match parse_addr(&req.bind_address, req.bind_port) {
            Ok(a) => a,
            Err(e) => return Ok(rejected(format!("invalid bind address: {e}"))),
        };

        let fingerprint = match compute_fingerprint_from_pem(&req.certificate_pem) {
            Ok(fp) => fp,
            Err(e) => return Ok(rejected(format!("invalid certificate PEM: {e}"))),
        };

        if req.private_key_ref.trim().is_empty() {
            return Ok(rejected("private_key_ref must not be empty".to_string()));
        }

        let enabled = req.is_active.unwrap_or(true);

        if let Err(e) = self.server_key_store.add(
            addr,
            &req.certificate_pem,
            &req.private_key_pem,
            &req.private_key_ref,
            &req.common_name,
            &fingerprint,
            req.inspection_bypass,
            enabled,
        ) {
            tracing::error!(
                id = %req.id,
                addr = %addr,
                error = %e,
                "upload_server_certificate: add failed"
            );
            return Ok(rejected(format!("failed to register key: {e}")));
        }

        tracing::info!(
            id = %req.id,
            addr = %addr,
            cn = %req.common_name,
            fingerprint = %fingerprint,
            "server certificate uploaded"
        );

        Ok(Response::new(UploadServerCertificateResponse {
            accepted: true,
            fingerprint,
            error: String::new(),
        }))
    }
}

fn rejected(error: String) -> Response<UploadServerCertificateResponse> {
    Response::new(UploadServerCertificateResponse {
        accepted: false,
        fingerprint: String::new(),
        error,
    })
}

fn parse_addr(bind_address: &str, bind_port: u32) -> anyhow::Result<SocketAddr> {
    let ip = bind_address
        .parse()
        .map_err(|e| anyhow::anyhow!("'{bind_address}': {e}"))?;
    let port = if bind_port == 0 { 443 } else { bind_port as u16 };
    Ok(SocketAddr::new(ip, port))
}

fn compute_fingerprint_from_pem(cert_pem: &str) -> anyhow::Result<String> {
    let chain = parse_cert_chain_pem(cert_pem)?;
    let leaf = chain
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty certificate chain"))?;
    Ok(compute_fingerprint(leaf.as_ref()))
}

fn prepare_socket(socket_path: &str) -> std::io::Result<()> {
    let path = Path::new(socket_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn cleanup_socket(socket_path: &str) {
    if let Err(e) = std::fs::remove_file(socket_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(socket = socket_path, error = %e, "failed to remove server-cert socket");
    }
}
