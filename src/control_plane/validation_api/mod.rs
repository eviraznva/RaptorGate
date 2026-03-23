use std::path::Path;

use tokio::net::UnixListener;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

use crate::control_plane::error::ControlPlaneError;
use crate::rule_tree::parsing::parse_rule_tree;

pub mod proto;

use proto::raptorgate::control::raptor_lang_validation_service_server::{
    RaptorLangValidationService, RaptorLangValidationServiceServer,
};
use proto::raptorgate::control::{ValidateRaptorLangRequest, ValidateRaptorLangResponse};

pub async fn run(socket_path: &str, shutdown: CancellationToken) -> Result<(), ControlPlaneError> {
    prepare_socket(socket_path)?;

    let listener = bind_listener(socket_path)?;
    let incoming =
        UnixListenerStream::new(listener).map(|stream| stream.map_err(ControlPlaneError::from));

    tracing::info!(
        socket = socket_path,
        "Starting control plane validation gRPC server"
    );

    let result = tonic::transport::Server::builder()
        .add_service(RaptorLangValidationServiceServer::new(
            ValidationService::default(),
        ))
        .serve_with_incoming_shutdown(incoming, shutdown.cancelled())
        .await
        .map_err(ControlPlaneError::Serve);
    cleanup_socket(socket_path);
    result
}

fn bind_listener(socket_path: &str) -> Result<UnixListener, ControlPlaneError> {
    let listener = UnixListener::bind(socket_path)?;
    tracing::info!(socket = socket_path, "Validation gRPC socket bound");
    Ok(listener)
}

fn prepare_socket(socket_path: &str) -> Result<(), ControlPlaneError> {
    let path = Path::new(socket_path);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if path.exists() {
        tracing::info!(
            socket = socket_path,
            "Removing stale validation gRPC socket"
        );
        std::fs::remove_file(path)?;
    }

    Ok(())
}

fn cleanup_socket(socket_path: &str) {
    if let Err(err) = std::fs::remove_file(socket_path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(socket = socket_path, error = %err, "Failed to remove validation gRPC socket");
        }
    }
}

#[derive(Default)]
struct ValidationService;

#[tonic::async_trait]
impl RaptorLangValidationService for ValidationService {
    async fn validate_raptor_lang(
        &self,
        request: Request<ValidateRaptorLangRequest>,
    ) -> Result<Response<ValidateRaptorLangResponse>, Status> {
        let dsl = request.into_inner().dsl;
        let dsl_len = dsl.len();

        tracing::info!(dsl_len, "ValidateRaptorLang request received");

        let response = match parse_rule_tree(&dsl) {
            Ok(_) => {
                tracing::info!(dsl_len, "ValidateRaptorLang request valid");
                ValidateRaptorLangResponse {
                    is_valid: true,
                    error_message: String::new(),
                }
            }
            Err(err) => {
                tracing::warn!(dsl_len, error = %err, "ValidateRaptorLang request invalid");
                ValidateRaptorLangResponse {
                    is_valid: false,
                    error_message: err.to_string(),
                }
            }
        };

        Ok(Response::new(response))
    }
}
