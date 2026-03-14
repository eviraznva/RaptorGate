use uuid::Uuid;
use std::sync::Arc;
use serde_json::json;
use std::str::FromStr;
use tokio::sync::Mutex;
use tokio::time::sleep;
use std::time::Duration;
use std::collections::HashMap;
use redis::{FromRedisValue, Value};
use redis::aio::MultiplexedConnection;
use anyhow::{anyhow, Context, Result};

use crate::control_plane::firewall_rules_sync::FirewallRulesSyncOrchestrator;
use crate::control_plane::redis_events::{RedisEventPayload, RedisStreamEnvelope, RedisStreamName};

const REDIS_BATCH_SIZE: usize = 32;
const REDIS_BLOCK_MS: u64 = 5000;
const REDIS_IDLE_CHECK_COUNT: usize = 20;

#[derive(Debug, Clone)]
pub struct RedisTransportConfig {
    pub redis_url: String,
    pub consumer_group: String,
    pub consumer_name: String,
    pub pending_idle_ms: u64,
    pub max_retry_backoff_ms: u64,
    pub max_delivery_attempts: u32,
    pub dead_letter_stream: String,
}

#[derive(Clone)]
pub struct RedisEventPublisher {
    redis_url: String,
    producer_name: String,
    connection: Arc<Mutex<Option<MultiplexedConnection>>>,
}

pub struct RedisEventConsumer {
    cfg: RedisTransportConfig,
    connection: Arc<Mutex<Option<MultiplexedConnection>>>,
    orchestrator: Arc<FirewallRulesSyncOrchestrator>,
}

async fn connect_to_redis(redis_url: &str, label: &str) -> Result<MultiplexedConnection> {
    let client = redis::Client::open(redis_url)
        .with_context(|| format!("Invalid Redis URL: {redis_url}"))?;

    let connection = client
        .get_multiplexed_async_connection()
        .await
        .with_context(|| format!("Failed to connect to Redis for {label}"))?;

    Ok(connection)
}

async fn connect_with_retry(redis_url: &str, label: &str) -> MultiplexedConnection {
    let mut attempt = 0u32;
    loop {
        attempt = attempt.saturating_add(1);
        match connect_to_redis(redis_url, label).await {
            Ok(conn) => {
                println!("[Redis/{label}] Connected successfully");
                return conn;
            }
            Err(err) => {
                let backoff_ms = (250u64.saturating_mul(2u64.saturating_pow(attempt.min(10)))).min(30_000);
                eprintln!(
                    "[Redis/{label}] Connection attempt {attempt} failed, retrying in {backoff_ms} ms: {err:#}"
                );
                sleep(Duration::from_millis(backoff_ms)).await;
            }
        }
    }
}

async fn ensure_connection(
    connection: &Mutex<Option<MultiplexedConnection>>,
    redis_url: &str,
    label: &str,
) -> Result<()> {
    let mut guard = connection.lock().await;
    if guard.is_none() {
        let conn = connect_to_redis(redis_url, label).await?;
        *guard = Some(conn);
    }
    Ok(())
}

impl RedisEventPublisher {
    pub fn new(redis_url: &str, producer_name: impl Into<String>) -> Self {
        Self {
            redis_url: redis_url.to_string(),
            producer_name: producer_name.into(),
            connection: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn publish(&self, payload: RedisEventPayload, correlation_id: impl Into<String>) -> Result<String> {
        let envelope = RedisStreamEnvelope::new(payload, correlation_id, self.producer_name.clone());

        let stream_name = envelope.stream_name.as_str();
        let fields = envelope.to_stream_fields()?;

        let mut cmd = redis::cmd("XADD");
        cmd.arg(stream_name).arg("*");

        for (key, value) in fields {
            cmd.arg(key).arg(value);
        }

        ensure_connection(&self.connection, &self.redis_url, "publisher").await?;
        
        let mut guard = self.connection.lock().await;
        let conn = guard.as_mut().ok_or_else(|| anyhow!("Redis publisher not connected"))?;

        let entry_id: String = cmd
            .query_async(conn)
            .await
            .with_context(|| format!("Failed to XADD into stream {stream_name}"))?;

        Ok(entry_id)
    }
}

impl RedisEventConsumer {
    pub fn new(
        cfg: RedisTransportConfig,
        orchestrator: Arc<FirewallRulesSyncOrchestrator>,
    ) -> Self {
        Self {
            cfg,
            connection: Arc::new(Mutex::new(None)),
            orchestrator,
        }
    }

    async fn ensure_connected(&self) -> Result<()> {
        let mut guard = self.connection.lock().await;
        if guard.is_none() {
            let conn = connect_to_redis(&self.cfg.redis_url, "consumer").await?;
            *guard = Some(conn);
        }
        Ok(())
    }

    async fn get_connection(&self) -> Result<tokio::sync::MutexGuard<'_, Option<MultiplexedConnection>>> {
        let guard = self.connection.lock().await;
        if guard.is_none() {
            return Err(anyhow!("Redis consumer not connected"));
        }
        Ok(guard)
    }

    async fn reset_connection(&self) {
        let mut guard = self.connection.lock().await;
        *guard = None;
    }

    pub async fn ensure_consumer_groups(&self) -> Result<()> {
        let streams = RedisStreamName::control_plane_streams();

        let mut guard = self.connection.lock().await;
        let conn = guard.as_mut().ok_or_else(|| anyhow!("Redis consumer not connected"))?;

        for stream in streams {
            let reply = redis::cmd("XGROUP")
                .arg("CREATE")
                .arg(stream.as_str())
                .arg(&self.cfg.consumer_group)
                .arg("0")
                .arg("MKSTREAM")
                .query_async::<Value>(conn)
                .await;

            match reply {
                Ok(_) => {}
                Err(err) => {
                    let message = err.to_string();
                    if !message.contains("BUSYGROUP") {
                        return Err(err).with_context(|| {
                            format!(
                                "Failed to create consumer group {} for stream {}",
                                self.cfg.consumer_group,
                                stream.as_str()
                            )
                        });
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        // Wait until we can connect to Redis
        let conn = connect_with_retry(&self.cfg.redis_url, "consumer").await;
        {
            let mut guard = self.connection.lock().await;
            *guard = Some(conn);
        }

        self.ensure_consumer_groups().await?;

        let mut consecutive_failures = 0u32;

        loop {
            match self.run_iteration().await {
                Ok(()) => {
                    consecutive_failures = 0;
                }
                Err(err) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);

                    let backoff = self.compute_backoff(consecutive_failures);

                    eprintln!(
                        "Redis consumer iteration failed (attempt {}), retrying in {} ms: {err:#}",
                        consecutive_failures,
                        backoff.as_millis()
                    );

                    // Reset connection so we reconnect on next iteration
                    self.reset_connection().await;

                    sleep(backoff).await;

                    // Reconnect before retrying
                    let conn = connect_with_retry(&self.cfg.redis_url, "consumer").await;
                    {
                        let mut guard = self.connection.lock().await;
                        *guard = Some(conn);
                    }
                }
            }
        }
    }

    async fn run_iteration(&self) -> Result<()> {
        self.reclaim_pending_messages().await?;

        let envelopes = self.read_new_messages().await?;

        for envelope in envelopes {
            self.process_with_retry(&envelope).await?;
        }

        Ok(())
    }

    async fn reclaim_pending_messages(&self) -> Result<()> {
        for stream in RedisStreamName::control_plane_streams() {
            let pending = self.auto_claim(stream).await?;

            for envelope in pending {
                self.process_with_retry(&envelope).await?;
            }
        }

        Ok(())
    }

    async fn auto_claim(&self, stream: RedisStreamName) -> Result<Vec<RedisStreamEnvelope>> {
        let raw = {
            let mut guard = self.connection.lock().await;
            let conn = guard.as_mut().ok_or_else(|| anyhow!("Redis consumer not connected"))?;

            redis::cmd("XAUTOCLAIM")
                .arg(stream.as_str())
                .arg(&self.cfg.consumer_group)
                .arg(&self.cfg.consumer_name)
                .arg(self.cfg.pending_idle_ms)
                .arg("0-0")
                .arg("COUNT")
                .arg(REDIS_IDLE_CHECK_COUNT)
                .query_async::<Value>(conn)
                .await
                .with_context(|| {
                    format!(
                        "Failed to reclaim pending Redis events from stream {}",
                        stream.as_str()
                    )
                })?
        };

        parse_xautoclaim_reply(stream.as_str(), raw)
    }

    async fn read_new_messages(&self) -> Result<Vec<RedisStreamEnvelope>> {
        let streams = RedisStreamName::control_plane_streams();

        let stream_names: Vec<&str> = streams.iter().map(RedisStreamName::as_str).collect();
        let ids = vec![">"; stream_names.len()];

        let raw = {
            let mut guard = self.connection.lock().await;
            let conn = guard.as_mut().ok_or_else(|| anyhow!("Redis consumer not connected"))?;

            redis::cmd("XREADGROUP")
                .arg("GROUP")
                .arg(&self.cfg.consumer_group)
                .arg(&self.cfg.consumer_name)
                .arg("COUNT")
                .arg(REDIS_BATCH_SIZE)
                .arg("BLOCK")
                .arg(REDIS_BLOCK_MS)
                .arg("STREAMS")
                .arg(stream_names.clone())
                .arg(ids)
                .query_async::<Value>(conn)
                .await
                .context("Failed to read control-plane events from Redis")?
        };

        parse_xreadgroup_reply(raw)
    }

    async fn process_with_retry(&self, envelope: &RedisStreamEnvelope) -> Result<()> {
        let mut attempt = 0u32;

        loop {
            match self.handle_envelope(envelope).await {
                Ok(()) => {
                    self.ack(envelope).await?;
                    return Ok(());
                }
                Err(err) => {
                    attempt = attempt.saturating_add(1);

                    if attempt >= self.cfg.max_delivery_attempts.max(1) {
                        self.move_to_dead_letter(envelope, &err.to_string(), attempt).await?;
                        self.ack(envelope).await?;

                        eprintln!(
                            "Redis event {} moved to dead-letter stream {} after {} failed attempts",
                            envelope.stream_entry_id.as_deref().unwrap_or("unknown"),
                            self.cfg.dead_letter_stream,
                            attempt
                        );

                        return Ok(());
                    }

                    let backoff = self.compute_backoff(attempt);

                    eprintln!(
                        "Redis event handling failed for {} on {} (attempt {}), retrying in {} ms: {err:#}",
                        envelope.stream_entry_id.as_deref().unwrap_or("unknown"),
                        envelope.stream_name.as_str(),
                        attempt,
                        backoff.as_millis()
                    );

                    sleep(backoff).await;
                }
            }
        }
    }

    async fn move_to_dead_letter(
        &self,
        envelope: &RedisStreamEnvelope,
        error_message: &str,
        attempt_count: u32,
    ) -> Result<()> {
        let payload_json = envelope.to_json()?;

        let metadata_json = serde_json::to_string(&json!({
            "source_stream": envelope.stream_name.as_str(),
            "source_entry_id": envelope.stream_entry_id,
            "consumer_group": self.cfg.consumer_group,
            "consumer_name": self.cfg.consumer_name,
            "attempt_count": attempt_count,
            "dead_letter_reason": error_message,
            "moved_at_unix": time::OffsetDateTime::now_utc().unix_timestamp(),
        })).context("Failed to serialize dead-letter metadata")?;

        let mut guard = self.connection.lock().await;
        let conn = guard.as_mut().ok_or_else(|| anyhow!("Redis consumer not connected"))?;

        let _: String = redis::cmd("XADD")
            .arg(&self.cfg.dead_letter_stream)
            .arg("*")
            .arg("event_id")
            .arg(envelope.event_id.clone())
            .arg("correlation_id")
            .arg(envelope.correlation_id.clone())
            .arg("producer")
            .arg(envelope.producer.clone())
            .arg("event_type")
            .arg(envelope.payload.event_type())
            .arg("payload")
            .arg(payload_json)
            .arg("metadata")
            .arg(metadata_json)
            .query_async(conn)
            .await
            .with_context(|| {
                format!(
                    "Failed to move event {} to dead-letter stream {}",
                    envelope.event_id,
                    self.cfg.dead_letter_stream
                )
            })?;

        Ok(())
    }

    fn compute_backoff(&self, attempt: u32) -> Duration {
        let max_ms = self.cfg.max_retry_backoff_ms.max(100);
        let exp = 2u64.saturating_pow(attempt.min(10));
        let backoff_ms = (250u64.saturating_mul(exp)).min(max_ms);

        Duration::from_millis(backoff_ms)
    }

    async fn handle_envelope(&self, envelope: &RedisStreamEnvelope) -> Result<()> {
        let correlation_id = Uuid::from_str(&envelope.correlation_id)
            .context("Failed to parse correlation_id")?;

        match &envelope.payload {
            RedisEventPayload::ConfigBundleChanged(_) => {
                self.orchestrator.on_config_bundle_changed(correlation_id).await
            }
            RedisEventPayload::ConfigResyncAvailable(_) => {
                self.orchestrator.on_resync_available(correlation_id).await
            }
            RedisEventPayload::ConfigBundleRollbackChanged(event) => self
                .orchestrator
                .on_rollback_requested(event.target_config_version, correlation_id)
                .await,
            RedisEventPayload::SecurityAlertRaised(_) => Ok(()),
        }.with_context(|| {
            let entry_id = envelope.stream_entry_id.as_deref().unwrap_or("unknown");

            format!(
                "Failed to handle Redis event {} from stream {}",
                entry_id,
                envelope.stream_name.as_str()
            )
        })
    }

    async fn ack(&self, envelope: &RedisStreamEnvelope) -> Result<()> {
        let Some(entry_id) = envelope.stream_entry_id.as_deref() else {
            return Ok(());
        };

        let mut guard = self.connection.lock().await;
        let conn = guard.as_mut().ok_or_else(|| anyhow!("Redis consumer not connected"))?;

        let _: i64 = redis::cmd("XACK")
            .arg(envelope.stream_name.as_str())
            .arg(&self.cfg.consumer_group)
            .arg(entry_id)
            .query_async(conn)
            .await
            .with_context(|| {
                format!(
                    "Failed to acknowledge Redis event {} on stream {}",
                    entry_id,
                    envelope.stream_name.as_str()
                )
            })?;

        Ok(())
    }
}

fn parse_xreadgroup_reply(raw: Value) -> Result<Vec<RedisStreamEnvelope>> {
    let mut envelopes = Vec::new();

    let Value::Array(streams) = raw else {
        return Ok(envelopes);
    };

    for stream in streams {
        let Value::Array(parts) = stream else {
            continue;
        };

        if parts.len() != 2 {
            continue;
        }

        let stream_name = String::from_redis_value(parts[0].clone())
            .context("Failed to parse stream name from Redis reply")?;

        let Value::Array(entries) = &parts[1] else {
            continue;
        };

        for entry in entries {
            if let Some(envelope) = parse_stream_entry(&stream_name, entry)? {
                envelopes.push(envelope);
            }
        }
    }

    Ok(envelopes)
}

fn parse_xautoclaim_reply(stream_name: &str, raw: Value) -> Result<Vec<RedisStreamEnvelope>> {
    let Value::Array(parts) = raw else {
        return Ok(Vec::new());
    };

    if parts.len() < 2 {
        return Ok(Vec::new());
    }

    let Value::Array(entries) = &parts[1] else {
        return Ok(Vec::new());
    };

    let mut envelopes = Vec::new();

    for entry in entries {
        if let Some(envelope) = parse_stream_entry(stream_name, entry)? {
            envelopes.push(envelope);
        }
    }

    Ok(envelopes)
}

fn parse_stream_entry(stream_name: &str, entry: &Value) -> Result<Option<RedisStreamEnvelope>> {
    let Value::Array(entry_parts) = entry else {
        return Ok(None);
    };

    if entry_parts.len() != 2 {
        return Ok(None);
    }

    let entry_id = String::from_redis_value(entry_parts[0].clone())
        .context("Failed to parse stream entry id from Redis reply")?;

    let fields = parse_field_map(&entry_parts[1])?;
    let envelope = RedisStreamEnvelope::from_stream_entry(stream_name, entry_id, &fields)?;

    Ok(Some(envelope))
}

fn parse_field_map(value: &Value) -> Result<HashMap<String, String>> {
    let Value::Array(items) = value else {
        return Ok(HashMap::new());
    };

    let mut result = HashMap::new();
    let mut chunks = items.chunks_exact(2);

    for pair in &mut chunks {
        let key = String::from_redis_value(pair[0].clone()).context("Failed to parse Redis field key")?;
        let value = String::from_redis_value(pair[1].clone()).context("Failed to parse Redis field value")?;

        result.insert(key, value);
    }

    Ok(result)
}
