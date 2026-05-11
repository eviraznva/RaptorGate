use std::path::Path;

use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

use crate::proto::control::raptor_lang_validation_service_server::{
    RaptorLangValidationService, RaptorLangValidationServiceServer,
};
use crate::proto::control::{ValidateRaptorLangRequest, ValidateRaptorLangResponse};
use crate::rule_tree::parsing::parse_rule_tree;

#[derive(Clone, Default)]
pub struct RaptorLangValidationHandler;

#[tonic::async_trait]
impl RaptorLangValidationService for RaptorLangValidationHandler {
    async fn validate_raptor_lang(
        &self,
        request: Request<ValidateRaptorLangRequest>,
    ) -> Result<Response<ValidateRaptorLangResponse>, Status> {
        match parse_rule_tree(&request.into_inner().dsl) {
            Ok(_) => Ok(Response::new(ValidateRaptorLangResponse {
                is_valid: true,
                error_message: String::new(),
            })),
            Err(err) => Ok(Response::new(ValidateRaptorLangResponse {
                is_valid: false,
                error_message: err.to_string(),
            })),
        }
    }
}

pub struct ControlServer {
    socket_path: String,
    shutdown: CancellationToken,
}

impl ControlServer {
    pub fn new(socket_path: impl Into<String>, shutdown: CancellationToken) -> Self {
        Self {
            socket_path: socket_path.into(),
            shutdown,
        }
    }

    pub async fn serve(self) {
        if let Err(err) = prepare_socket(&self.socket_path) {
            tracing::error!(
                socket = self.socket_path,
                error = %err,
                "failed to prepare control socket"
            );
            return;
        }

        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!(
                    socket = self.socket_path,
                    error = %err,
                    "failed to bind control socket"
                );
                return;
            }
        };

        tracing::info!(
            event = "grpc.control_service.listening",
            socket = self.socket_path,
            "RaptorLangValidationService listening"
        );

        let incoming = UnixListenerStream::new(listener);

        if let Err(err) = tonic::transport::Server::builder()
            .add_service(RaptorLangValidationServiceServer::new(
                RaptorLangValidationHandler,
            ))
            .serve_with_incoming_shutdown(incoming, self.shutdown.cancelled())
            .await
        {
            tracing::error!(error = %err, "RaptorLangValidationService server error");
        }

        cleanup_socket(&self.socket_path);
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
    if let Err(err) = std::fs::remove_file(socket_path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(socket = socket_path, error = %err, "failed to remove control socket");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepts_valid_raptorlang() {
        let response = RaptorLangValidationHandler
            .validate_raptor_lang(Request::new(ValidateRaptorLangRequest {
                dsl: "match protocol { = tcp : verdict allow }".into(),
            }))
            .await
            .expect("validation request should not fail")
            .into_inner();

        assert!(response.is_valid);
        assert!(response.error_message.is_empty());
    }

    #[tokio::test]
    async fn rejects_invalid_raptorlang() {
        let response = RaptorLangValidationHandler
            .validate_raptor_lang(Request::new(ValidateRaptorLangRequest {
                dsl: "match protocol { = tcp verdict allow }".into(),
            }))
            .await
            .expect("validation request should not fail")
            .into_inner();

        assert!(!response.is_valid);
        assert!(!response.error_message.is_empty());
    }
}
