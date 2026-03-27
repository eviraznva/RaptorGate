use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

use crate::data_plane::nat::engine::NatEngine;
use crate::data_plane::policy_store::PolicyStore;
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::policy::compiler;
use crate::proto::services::firewall_query_service_server::{
    FirewallQueryService, FirewallQueryServiceServer,
};
use crate::proto::services::{
    GetNatBindingsRequest, GetNatBindingsResponse,
    GetTcpSessionsRequest, GetTcpSessionsResponse,
    ValidateRaptorlangRequest, ValidateRaptorlangResponse,
};

pub struct QueryServer {
    handler: QueryHandler,
    socket_path: String,
    shutdown: CancellationToken,
}

impl QueryServer {
    pub fn new(
        handler: QueryHandler,
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
            tracing::error!(socket = self.socket_path, error = %e, "failed to prepare query socket");
            return;
        }

        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(socket = self.socket_path, error = %e, "failed to bind query socket");
                return;
            }
        };

        tracing::info!(socket = self.socket_path, "FirewallQueryService listening");

        let incoming = UnixListenerStream::new(listener);

        if let Err(e) = tonic::transport::Server::builder()
            .add_service(FirewallQueryServiceServer::new(self.handler))
            .serve_with_incoming_shutdown(incoming, self.shutdown.cancelled())
            .await
        {
            tracing::error!(error = %e, "FirewallQueryService server error");
        }

        cleanup_socket(&self.socket_path);
    }
}

#[derive(Clone)]
pub struct QueryHandler {
    pub tcp_tracker: Arc<TcpSessionTracker>,
    pub nat_engine: Arc<Mutex<NatEngine>>,
    pub policy_store: Arc<PolicyStore>,
}

#[tonic::async_trait]
impl FirewallQueryService for QueryHandler {
    async fn get_tcp_sessions(
        &self,
        _request: Request<GetTcpSessionsRequest>,
    ) -> Result<Response<GetTcpSessionsResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateRaptorlangRequest>,
    ) -> Result<Response<ValidateRaptorlangResponse>, Status> {
        let dsl = request.into_inner().raptorlang;
        let response = match compiler::compile_override(&dsl) {
            Ok(_) => ValidateRaptorlangResponse { error: None },
            Err(err) => ValidateRaptorlangResponse { error: Some(err.to_string()) },
        };
        Ok(Response::new(response))
    }

    async fn get_nat_bindings(
        &self,
        _request: Request<GetNatBindingsRequest>,
    ) -> Result<Response<GetNatBindingsResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }
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
        && e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(socket = socket_path, error = %e, "failed to remove query socket");
        }
}
