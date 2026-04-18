use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

use crate::data_plane::nat::{NatConfigProvider, NatEngine};
use crate::data_plane::nat::config::NatConfig;
use crate::data_plane::dns_inspection::config::DnsInspectionConfig;
use crate::data_plane::dns_inspection::dns_inspection::DnsInspection;
use crate::data_plane::dns_inspection::provider::DnsInspectionConfigProvider;
use crate::proto::common::CertificateType;
use crate::proto::services::firewall_config_snapshot_service_server::{
    FirewallConfigSnapshotService, FirewallConfigSnapshotServiceServer,
};
use crate::proto::services::{PushActiveConfigSnapshotRequest, PushActiveConfigSnapshotResponse};
use crate::tls::{EchTlsPolicy, ServerKeyStore, TlsDecisionEngine};

pub struct SnapshotServer {
    handler: SnapshotHandler,
    socket_path: String,
    shutdown: CancellationToken,
}

impl SnapshotServer {
    pub fn new(
        handler: SnapshotHandler,
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
            tracing::error!(socket = self.socket_path, error = %e, "failed to prepare snapshot socket");
            return;
        }

        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(socket = self.socket_path, error = %e, "failed to bind snapshot socket");
                return;
            }
        };

        tracing::info!(socket = self.socket_path, "SnapshotServer listening");
        let incoming = UnixListenerStream::new(listener);

        if let Err(e) = tonic::transport::Server::builder()
            .add_service(FirewallConfigSnapshotServiceServer::new(self.handler))
            .serve_with_incoming_shutdown(incoming, self.shutdown.cancelled())
            .await
        {
            tracing::error!(error = %e, "SnapshotServer error");
        }

        cleanup_socket(&self.socket_path);
    }
}

pub struct SnapshotHandler {
    pub decision_engine: Arc<TlsDecisionEngine>,
    pub server_key_store: Arc<ServerKeyStore>,
    pub dns_inspection_store: Arc<DnsInspectionConfigProvider>,
    pub dns_inspection: Arc<DnsInspection>,
    pub nat_store: Arc<NatConfigProvider>,
    pub nat_engine: Arc<Mutex<NatEngine>>,
}

#[tonic::async_trait]
impl FirewallConfigSnapshotService for SnapshotHandler {
    // Przyjmuje snapshot konfiguracji z backendu i aplikuje bypass + klucze serwerowe.
    async fn push_active_config_snapshot(
        &self,
        request: Request<PushActiveConfigSnapshotRequest>,
    ) -> Result<Response<PushActiveConfigSnapshotResponse>, Status> {
        let req = request.into_inner();
        let correlation_id = req.correlation_id.clone();

        let snapshot = req
            .snapshot
            .ok_or_else(|| Status::invalid_argument("missing snapshot"))?;
        let bundle = snapshot
            .bundle
            .ok_or_else(|| Status::invalid_argument("missing bundle"))?;

        // 1. Bypass domains
        let bypass_domains: Vec<String> = bundle
            .ssl_bypass_list
            .iter()
            .map(|e| e.domain.clone())
            .collect();
        self.decision_engine.reload_bypass(&bypass_domains);

        // 2. Reconcile server keys (desired-state)
        if let Err(e) = self.reconcile_server_keys(&bundle.firewall_certificates) {
            tracing::error!(error = %e, "server key reconciliation failed");
            return Ok(Response::new(PushActiveConfigSnapshotResponse {
                correlation_id,
                accepted: false,
                message: format!("server key reconciliation failed: {e}"),
                applied_snapshot_id: String::new(),
            }));
        }

        // 3. TLS inspection policy (ECH + pinning)
        if let Some(ref policy) = bundle.tls_inspection_policy {
            self.decision_engine.reload_ech_policy(EchTlsPolicy {
                block_ech_no_sni: policy.block_ech_no_sni,
                block_all_ech: policy.block_all_ech,
            });
            self.decision_engine
                .reload_known_pinned_domains(&policy.known_pinned_domains);
            if let Err(e) = self.apply_dns_ech_policy(policy).await {
                tracing::error!(error = %e, "DNS ECH policy apply failed");
                return Ok(Response::new(PushActiveConfigSnapshotResponse {
                    correlation_id,
                    accepted: false,
                    message: format!("dns ech policy apply failed: {e}"),
                    applied_snapshot_id: String::new(),
                }));
            }
        }

        // 4. NAT rules
        if let Err(e) = self.apply_nat_rules(&bundle.nat_rules).await {
            tracing::error!(error = %e, "NAT snapshot apply failed");
            return Ok(Response::new(PushActiveConfigSnapshotResponse {
                correlation_id,
                accepted: false,
                message: format!("nat snapshot apply failed: {e}"),
                applied_snapshot_id: String::new(),
            }));
        }

        tracing::info!(
            snapshot_id = snapshot.id,
            bypass_count = bypass_domains.len(),
            certs = bundle.firewall_certificates.len(),
            nat_rules = bundle.nat_rules.len(),
            "config snapshot applied"
        );

        Ok(Response::new(PushActiveConfigSnapshotResponse {
            correlation_id,
            accepted: true,
            message: String::new(),
            applied_snapshot_id: snapshot.id,
        }))
    }
}

impl SnapshotHandler {
    async fn apply_nat_rules(
        &self,
        rules: &[crate::proto::config::NatRule],
    ) -> anyhow::Result<()> {
        let nat_config = NatConfig::from_proto_rules(rules)?;
        let runtime_rules = nat_config.to_runtime_rules()?;

        self.nat_store.swap_config(nat_config).await?;

        let mut engine = self.nat_engine.lock().await;
        engine.replace_rules(&runtime_rules);
        Ok(())
    }

    async fn apply_dns_ech_policy(
        &self,
        policy: &crate::proto::config::TlsInspectionPolicy,
    ) -> anyhow::Result<()> {
        let current = self.dns_inspection_store.get_config();
        let mut new_config: DnsInspectionConfig = (**current).clone();
        new_config.ech_mitigation.strip_ech_dns = policy.strip_ech_dns;
        new_config.ech_mitigation.log_ech_attempts = policy.log_ech_attempts;
        self.dns_inspection_store
            .swap_config(new_config.clone())
            .await?;
        self.dns_inspection.update_config(&new_config)?;
        Ok(())
    }

    // Odrzuca snapshot, jesli brakuje key_ref w ServerKeyStore.
    fn reconcile_server_keys(
        &self,
        certs: &[crate::proto::config::FirewallCertificate],
    ) -> anyhow::Result<()> {
        let tls_server_certs: Vec<_> = certs
            .iter()
            .filter(|c| c.cert_type == CertificateType::TlsServer as i32)
            .collect();

        let current: std::collections::HashMap<SocketAddr, _> = self
            .server_key_store
            .list()
            .into_iter()
            .map(|entry| (entry.addr, entry))
            .collect();
        let mut desired = std::collections::HashMap::new();

        for cert in tls_server_certs {
            let addr = parse_bind_addr(cert)?;
            if desired.insert(addr, cert).is_some() {
                anyhow::bail!("duplicate TLS server certificate bind address: {addr}");
            }
        }

        let missing: Vec<String> = desired
            .iter()
            .filter(|(addr, cert)| match current.get(addr) {
                Some(e) => e.key_ref != cert.private_key_ref,
                None => true,
            })
            .map(|(_, cert)| cert.id.clone())
            .collect();

        if !missing.is_empty() {
            anyhow::bail!(
                "missing server keys on firewall (run UploadServerCertificate first): {}",
                missing.join(", ")
            );
        }

        for (addr, cert) in &desired {
            let existing = current
                .get(addr)
                .expect("missing entries rejected above");

            let metadata_changed = existing.fingerprint != cert.fingerprint
                || existing.certificate_pem != cert.certificate_pem
                || existing.common_name != cert.common_name
                || existing.bypass != cert.inspection_bypass;

            if metadata_changed {
                self.server_key_store.load(
                    *addr,
                    &cert.certificate_pem,
                    &cert.private_key_ref,
                    &cert.common_name,
                    &cert.fingerprint,
                    cert.inspection_bypass,
                )?;
                tracing::debug!(%addr, cn = %cert.common_name, "server key metadata refreshed");
            }
        }

        for entry in current.values() {
            if !desired.contains_key(&entry.addr) {
                let _ = self.server_key_store.remove(entry.addr, &entry.key_ref);
                tracing::info!(addr = %entry.addr, "removed server key not in desired state");
            }
        }

        Ok(())
    }
}

fn parse_bind_addr(cert: &crate::proto::config::FirewallCertificate) -> anyhow::Result<SocketAddr> {
    let ip = cert
        .bind_address
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind_address '{}': {e}", cert.bind_address))?;
    let port = if cert.bind_port == 0 {
        443
    } else {
        cert.bind_port as u16
    };
    Ok(SocketAddr::new(ip, port))
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
        tracing::warn!(socket = socket_path, error = %e, "failed to remove snapshot socket");
    }
}
