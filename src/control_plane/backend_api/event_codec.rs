use tokio_stream::wrappers::ReceiverStream;

use crate::control_plane::backend_api::proto::raptorgate::events::{
    BackendEvent, FirewallEvent, PolicyActivatedEvent, PolicyFailedEvent, ResyncConfirmedEvent,
};

pub const FW_HEARTBEAT: &str = "fw.heartbeat";
pub const FW_METRICS: &str = "fw.metrics";
pub const FW_POLICY_ACTIVATED: &str = "fw.policy_activated";
pub const FW_POLICY_FAILED: &str = "fw.policy_failed";
pub const FW_RESYNC_CONFIRMED: &str = "fw.resync_confirmed";
pub const BE_HEARTBEAT_ACK: &str = "be.heartbeat_ack";
pub const BE_CONFIG_CHANGED: &str = "be.config_changed";
pub const BE_RESYNC_REQUESTED: &str = "be.resync_requested";

pub fn receiver_stream(
    rx: tokio::sync::mpsc::Receiver<FirewallEvent>,
) -> ReceiverStream<FirewallEvent> {
    ReceiverStream::new(rx)
}

pub fn encode_firewall_event(event_type: &str, payload: impl prost::Message) -> FirewallEvent {
    FirewallEvent {
        event_id: uuid::Uuid::now_v7().to_string(),
        r#type: event_type.to_string(),
        payload: prost::Message::encode_to_vec(&payload),
        ts: Some(current_timestamp()),
    }
}

pub fn encode_policy_activated(payload: PolicyActivatedEvent) -> FirewallEvent {
    encode_firewall_event(FW_POLICY_ACTIVATED, payload)
}

pub fn encode_policy_failed(payload: PolicyFailedEvent) -> FirewallEvent {
    encode_firewall_event(FW_POLICY_FAILED, payload)
}

pub fn encode_resync_confirmed(payload: ResyncConfirmedEvent) -> FirewallEvent {
    encode_firewall_event(FW_RESYNC_CONFIRMED, payload)
}

pub fn decode_backend_payload<T: prost::Message + Default>(
    event: &BackendEvent,
) -> Result<T, prost::DecodeError> {
    T::decode(event.payload.as_ref())
}

pub fn current_timestamp() -> prost_types::Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    prost_types::Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    }
}
