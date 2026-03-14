use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RedisStreamName {
    ConfigBundleChanged,
    ConfigResyncAvailable,
    ConfigBundleRollbackChanged,
    SecurityAlerts,
}

impl RedisStreamName {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ConfigBundleChanged => "config.bundle.changed",
            Self::ConfigResyncAvailable => "config.resync.available",
            Self::ConfigBundleRollbackChanged => "config.bundle.rollback.changed",
            Self::SecurityAlerts => "security.alerts",
        }
    }

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "config.bundle.changed" => Ok(Self::ConfigBundleChanged),
            "config.resync.available" => Ok(Self::ConfigResyncAvailable),
            "config.bundle.rollback.changed" => Ok(Self::ConfigBundleRollbackChanged),
            "security.alerts" => Ok(Self::SecurityAlerts),
            _ => Err(anyhow!("Unsupported Redis stream name: {value}")),
        }
    }

    pub const fn control_plane_streams() -> [Self; 3] {
        [
            Self::ConfigBundleChanged,
            Self::ConfigResyncAvailable,
            Self::ConfigBundleRollbackChanged,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SeverityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisStreamEnvelope {
    pub stream_name: RedisStreamName, // 4 + 25 + 25 + 100 + 12  + 1024 = 1190B
    pub stream_entry_id: Option<String>,
    pub event_id: String,
    pub correlation_id: String,
    pub producer: String,
    pub occurred_at: OffsetDateTime,
    pub payload: RedisEventPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", content = "data", rename_all = "snake_case")]
pub enum RedisEventPayload {
    ConfigBundleChanged(ConfigBundleChangedEvent),
    ConfigResyncAvailable(ConfigResyncAvailableEvent),
    ConfigBundleRollbackChanged(ConfigBundleRollbackChangedEvent),
    SecurityAlertRaised(SecurityAlertRaisedEvent),
}

impl RedisEventPayload {
    pub const fn stream_name(&self) -> RedisStreamName {
        match self {
            Self::ConfigBundleChanged(_) => RedisStreamName::ConfigBundleChanged,
            Self::ConfigResyncAvailable(_) => RedisStreamName::ConfigResyncAvailable,
            Self::ConfigBundleRollbackChanged(_) => RedisStreamName::ConfigBundleRollbackChanged,
            Self::SecurityAlertRaised(_) => RedisStreamName::SecurityAlerts,
        }
    }

    pub fn event_type(&self) -> &'static str {
        match self {
            Self::ConfigBundleChanged(_) => "config_bundle_changed",
            Self::ConfigResyncAvailable(_) => "config_resync_available",
            Self::ConfigBundleRollbackChanged(_) => "config_bundle_rollback_changed",
            Self::SecurityAlertRaised(_) => "security_alert_raised",
        }
    }

    pub fn to_data_json(&self) -> Result<String> {
        let data = match self {
            Self::ConfigBundleChanged(value) => serde_json::to_string(value),
            Self::ConfigResyncAvailable(value) => serde_json::to_string(value),
            Self::ConfigBundleRollbackChanged(value) => serde_json::to_string(value),
            Self::SecurityAlertRaised(value) => serde_json::to_string(value),
        };

        data.context("Failed to serialize Redis event payload")
    }

    pub fn from_type_and_data(event_type: &str, payload_json: &str) -> Result<Self> {
        match event_type {
            "config_bundle_changed" => Ok(Self::ConfigBundleChanged(
                serde_json::from_str(payload_json)
                    .context("Failed to deserialize config_bundle_changed payload")?,
            )),
            "config_resync_available" => Ok(Self::ConfigResyncAvailable(
                serde_json::from_str(payload_json)
                    .context("Failed to deserialize config_resync_available payload")?,
            )),
            "config_bundle_rollback_changed" => Ok(Self::ConfigBundleRollbackChanged(
                serde_json::from_str(payload_json)
                    .context("Failed to deserialize config_bundle_rollback_changed payload")?,
            )),
            "security_alert_raised" => Ok(Self::SecurityAlertRaised(
                serde_json::from_str(payload_json)
                    .context("Failed to deserialize security_alert_raised payload")?,
            )),
            _ => Err(anyhow!("Unsupported Redis event type: {event_type}")),
        }
    }
}

impl RedisStreamEnvelope {
    pub fn new(
        payload: RedisEventPayload,
        correlation_id: impl Into<String>,
        producer: impl Into<String>,
    ) -> Self {
        let stream_name = payload.stream_name();

        Self {
            stream_name,
            stream_entry_id: None,
            event_id: Uuid::new_v4().to_string(),
            correlation_id: correlation_id.into(),
            producer: producer.into(),
            occurred_at: OffsetDateTime::now_utc(),
            payload,
        }
    }

    pub fn to_stream_fields(&self) -> Result<Vec<(String, String)>> {
        Ok(vec![
            ("event_id".to_string(), self.event_id.clone()),
            ("correlation_id".to_string(), self.correlation_id.clone()),
            ("producer".to_string(), self.producer.clone()),
            (
                "occurred_at_unix".to_string(),
                self.occurred_at.unix_timestamp().to_string(),
            ),
            (
                "event_type".to_string(),
                self.payload.event_type().to_string(),
            ),
            ("payload".to_string(), self.payload.to_data_json()?),
        ])
    }

    pub fn from_stream_entry(
        stream_name: &str,
        stream_entry_id: impl Into<String>,
        fields: &HashMap<String, String>,
    ) -> Result<Self> {
        let occurred_at_unix = fields
            .get("occurred_at_unix")
            .context("Missing occurred_at_unix field")?
            .parse::<i64>()
            .context("Invalid occurred_at_unix field")?;

        let event_type = fields
            .get("event_type")
            .context("Missing event_type field")?;

        let payload_json = fields.get("payload").context("Missing payload field")?;

        Ok(Self {
            stream_name: RedisStreamName::from_str(stream_name)?,
            stream_entry_id: Some(stream_entry_id.into()),
            event_id: fields
                .get("event_id")
                .cloned()
                .context("Missing event_id field")?,
            correlation_id: fields
                .get("correlation_id")
                .cloned()
                .context("Missing correlation_id field")?,
            producer: fields
                .get("producer")
                .cloned()
                .context("Missing producer field")?,
            occurred_at: OffsetDateTime::from_unix_timestamp(occurred_at_unix)
                .context("Invalid occurred_at_unix timestamp")?,
            payload: RedisEventPayload::from_type_and_data(event_type, payload_json)?,
        })
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).context("Failed to serialize Redis stream envelope")
    }

    pub fn event_log_value(&self) -> Result<serde_json::Value> {
        Ok(json!({
            "stream_name": self.stream_name.as_str(),
            "stream_entry_id": self.stream_entry_id,
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "producer": self.producer,
            "occurred_at_unix": self.occurred_at.unix_timestamp(),
            "payload": serde_json::from_str::<serde_json::Value>(&self.payload.to_data_json()?)?,
            "event_type": self.payload.event_type(),
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBundleChangedEvent {
    pub target_config_version: u64,
    pub config_bundle_checksum: String,
    pub reason: String,
    pub requested_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigResyncAvailableEvent {
    pub backend_instance: String,
    pub target_config_version: Option<u64>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBundleRollbackChangedEvent {
    pub previous_config_version: u64,
    pub target_config_version: u64,
    pub reason: String,
    pub initiated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlertRaisedEvent {
    pub log_id: String,
    pub occurred_at: OffsetDateTime,
    pub title: String,
    pub short_description: String,
    pub severity: SeverityLevel,
    pub config_version: u64,
}
