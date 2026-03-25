use tonic::transport::Channel;

use crate::control_plane::backend_api::event_codec::receiver_stream;
use crate::control_plane::backend_api::proto::raptorgate::config::{
    ConfigResponse, GetConfigRequest,
};
use crate::control_plane::backend_api::proto::raptorgate::events::{BackendEvent, FirewallEvent};
use crate::control_plane::backend_api::proto::raptorgate::raptor_gate_service_client::RaptorGateServiceClient;

#[derive(Clone)]
pub struct BackendApiClient {
    inner: RaptorGateServiceClient<Channel>,
}

pub struct EventStreamChannels {
    pub outbound: tokio::sync::mpsc::Sender<FirewallEvent>,
    pub inbound: tokio::sync::mpsc::Receiver<BackendEvent>,
    pub opened: tokio::sync::oneshot::Receiver<Result<(), tonic::Status>>,
    pub join: tokio::task::JoinHandle<()>,
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

    pub fn open_event_stream(&mut self, buffer_size: usize) -> EventStreamChannels {
        let (fw_tx, fw_rx) = tokio::sync::mpsc::channel::<FirewallEvent>(buffer_size);
        let (be_tx, be_rx) = tokio::sync::mpsc::channel::<BackendEvent>(buffer_size);
        let (opened_tx, opened_rx) = tokio::sync::oneshot::channel();
        let mut inner = self.inner.clone();

        let join = tokio::spawn(async move {
            let response = match inner.event_stream(receiver_stream(fw_rx)).await {
                Ok(response) => {
                    let _ = opened_tx.send(Ok(()));
                    response
                }
                Err(status) => {
                    let _ = opened_tx.send(Err(status));
                    return;
                }
            };

            let mut inbound = response.into_inner();
            while let Some(event) = inbound.message().await.transpose() {
                match event {
                    Ok(event) => {
                        if be_tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    Err(status) => {
                        tracing::warn!(%status, "Event stream receive error");
                        break;
                    }
                }
            }
        });

        EventStreamChannels {
            outbound: fw_tx,
            inbound: be_rx,
            opened: opened_rx,
            join,
        }
    }
}
