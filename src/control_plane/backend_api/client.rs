// Stub — event stream removed. Config fetch only.
use tonic::transport::Channel;

use crate::control_plane::backend_api::proto::raptorgate::config::{
    ConfigResponse, GetConfigRequest,
};
use crate::control_plane::backend_api::proto::raptorgate::raptor_gate_service_client::RaptorGateServiceClient;

#[derive(Clone)]
pub struct BackendApiClient {
    inner: RaptorGateServiceClient<Channel>,
}

impl BackendApiClient {
    pub async fn connect(socket_path: &str) -> Result<Self, tonic::transport::Error> {
        let socket_path = socket_path.to_owned();

        let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let path = socket_path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await?;

        Ok(Self {
            inner: RaptorGateServiceClient::new(channel),
        })
    }

    pub async fn get_active_config(
        &mut self,
        request: GetConfigRequest,
    ) -> Result<ConfigResponse, tonic::Status> {
        let response = self.inner.get_active_config(request).await?;
        Ok(response.into_inner())
    }
}
