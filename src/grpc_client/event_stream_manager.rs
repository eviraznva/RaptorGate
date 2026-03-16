use std::time::{Duration, Instant};

use tokio::sync::mpsc::{Receiver, Sender};

use crate::grpc_client::event_type::EventType;
use crate::grpc_client::client::make_firewall_event;
use crate::grpc_client::event_dispatcher::EventDispatcher;
use crate::grpc_client::firewall_mode_state::FirewallModeState;
use crate::grpc_client::proto_types::raptorgate::{
    telemetry::MetricsBatch,
    events::{FirewallEvent, HeartbeatEvent, HeartbeatAck, BackendEvent},
};

pub struct EventStreamManager {
    event_sender: Sender<FirewallEvent>,
    mode: FirewallModeState,
    start_time: Instant,
    firewall_version: String,
}

impl EventStreamManager {
    pub async fn start(
        fw_tx: Sender<FirewallEvent>,
        be_rx: Receiver<BackendEvent>,
        mode: FirewallModeState,
        firewall_version: String,
        heartbeat_interval_secs: u64,
        dispatcher: EventDispatcher,
    ) -> Result<Self, tonic::Status> {
        let start_time = Instant::now();

        let initial_hb = make_firewall_event(HeartbeatEvent::TYPE, HeartbeatEvent {
            firewall_version: firewall_version.clone(),
            mode: mode.get() as i32,
            active_config_version: mode.get_config_version(),
            uptime_seconds: 0,
        });

        fw_tx.try_send(initial_hb)
            .map_err(|_| tonic::Status::internal("EventStream channel full on initial heartbeat"))?;

        {
            let fw_tx = fw_tx.clone();
            let mode = mode.clone();
            let firewall_version = firewall_version.clone();

            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(Duration::from_secs(heartbeat_interval_secs));

                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    interval.tick().await;

                    let heartbeat = make_firewall_event(HeartbeatEvent::TYPE, HeartbeatEvent {
                        firewall_version: firewall_version.clone(),
                        mode: mode.get() as i32,
                        active_config_version: mode.get_config_version(),
                        uptime_seconds: start_time.elapsed().as_secs(),
                    });

                    let metrics = make_firewall_event(MetricsBatch::TYPE, MetricsBatch::default());

                    if let Err(e) = fw_tx.try_send(heartbeat) {
                        if matches!(e, tokio::sync::mpsc::error::TrySendError::Closed(_)) {
                            tracing::info!("EventStream closed, heartbeat task exiting");
                            break;
                        }
                        tracing::warn!("EventStream sender full, dropping HeartbeatEvent");
                    }
                    if let Err(e) = fw_tx.try_send(metrics) {
                        if matches!(e, tokio::sync::mpsc::error::TrySendError::Closed(_)) {
                            tracing::info!("EventStream closed, heartbeat task exiting");
                            break;
                        }
                        tracing::warn!("EventStream sender full, dropping MetricsBatch");
                    }
                }
            });
        }

        {
            let mut be_rx = be_rx;

            tokio::spawn(async move {
                while let Some(event) = be_rx.recv().await {
                    if event.r#type == HeartbeatAck::TYPE {
                        tracing::debug!("HeartbeatAck received");
                        continue;
                    }

                    match dispatcher.handlers.get(event.r#type.as_str()) {
                        Some(handler) => handler(event.payload.clone()).await,
                        None => tracing::warn!("Unknown BackendEvent type: {}", event.r#type),
                    }
                }
                tracing::info!("BackendEvent dispatcher finished — stream closed");
            });
        }

        Ok(Self {
            event_sender: fw_tx,
            mode,
            start_time,
            firewall_version,
        })
    }

    pub fn send_event<T: prost::Message + EventType>(&self, payload: T) -> Result<(), tonic::Status> {
        let event = make_firewall_event(T::TYPE, payload);

        self.event_sender.try_send(event).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) =>
                tonic::Status::resource_exhausted("EventStream channel full"),
            tokio::sync::mpsc::error::TrySendError::Closed(_) =>
                tonic::Status::unavailable("EventStream closed"),
        })
    }
}
