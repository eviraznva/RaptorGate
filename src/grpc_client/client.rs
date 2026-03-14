use tonic::transport::Channel;
use tokio_stream::wrappers::ReceiverStream;

use crate::grpc_client::proto_types::raptorgate::events::{BackendEvent, FirewallEvent};
use crate::grpc_client::proto_types::raptorgate::config::{ConfigResponse, GetConfigRequest};
use crate::grpc_client::proto_types::raptorgate::raptor_gate_service_client::RaptorGateServiceClient;

pub struct GrpcClient {
    inner: RaptorGateServiceClient<Channel>,
}

impl GrpcClient {
    pub async fn connect(socket_path: &str) -> Result<Self, tonic::transport::Error> {
        let socket_path = socket_path.to_owned();
        
        let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let path = socket_path.clone();
                
                async move {
                    let stream = tokio::net::UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            })).await?;
        
        Ok(Self {
            inner: RaptorGateServiceClient::new(channel),
        })
    }
    
    pub async fn get_active_config(&mut self, request: GetConfigRequest) 
        -> Result<ConfigResponse, tonic::Status> {
        let response = self.inner.get_active_config(request).await?;
        
        Ok(response.into_inner())
    }
    
    pub async fn open_event_stream(
        &mut self,
        buffer_size: usize,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<FirewallEvent>,
            tokio::sync::mpsc::Receiver<BackendEvent>,
        ),
        tonic::Status,
    > {
        let (fw_tx, fw_rx) = 
            tokio::sync::mpsc::channel::<FirewallEvent>(buffer_size);
        
        let (be_tx, be_rx) = 
            tokio::sync::mpsc::channel::<BackendEvent>(buffer_size);

        let response = self.inner
            .event_stream(ReceiverStream::new(fw_rx)).await?;
        
        let mut be_stream = response.into_inner();

        tokio::spawn(async move {
            while let Some(event) = be_stream.message().await.transpose() {
                match event {
                    Ok(ev) => {
                        if be_tx.send(ev).await.is_err() {
                            tracing::debug!("Backend event receiver dropped, stopping event stream task");
                            break;
                        }
                    }
                    Err(status) => {
                        tracing::warn!(%status, "Error receiving backend event, stopping event stream task");
                        break;
                    }
                }
            }
        });

        Ok((fw_tx, be_rx))
    }
}

pub fn make_firewall_event(event_type: &str, payload: impl prost::Message) -> FirewallEvent {
    FirewallEvent {
        event_id: uuid::Uuid::now_v7().to_string(),
        r#type: event_type.to_string(),
        payload: prost::Message::encode_to_vec(&payload),
        ts: Some(current_timestamp()),
    }
}

pub fn decode_backend_payload<T: prost::Message + Default>(event: &BackendEvent) 
    -> Result<T, prost::DecodeError> {
    T::decode(event.payload.as_ref())
}

fn current_timestamp() -> prost_types::Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    
    prost_types::Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    }
}
