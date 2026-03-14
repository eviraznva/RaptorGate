use crate::grpc_client::proto_types::raptorgate::telemetry::MetricsBatch;
use crate::grpc_client::proto_types::raptorgate::events::{
    AlertEvent, HeartbeatEvent, PolicyActivatedEvent, PolicyFailedEvent, ResyncConfirmedEvent,
    HeartbeatAck, ConfigChangedEvent, ResyncRequestedEvent,
};

pub trait EventType {
    const TYPE: &'static str;
}

impl EventType for HeartbeatEvent       { const TYPE: &'static str = "fw.heartbeat"; }
impl EventType for MetricsBatch         { const TYPE: &'static str = "fw.metrics"; }
impl EventType for AlertEvent           { const TYPE: &'static str = "fw.alert"; }
impl EventType for PolicyActivatedEvent { const TYPE: &'static str = "fw.policy_activated"; }
impl EventType for PolicyFailedEvent    { const TYPE: &'static str = "fw.policy_failed"; }
impl EventType for ResyncConfirmedEvent { const TYPE: &'static str = "fw.resync_confirmed"; }
impl EventType for HeartbeatAck         { const TYPE: &'static str = "be.heartbeat_ack"; }
impl EventType for ConfigChangedEvent   { const TYPE: &'static str = "be.config_changed"; }
impl EventType for ResyncRequestedEvent { const TYPE: &'static str = "be.resync_requested"; }