use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use prost_types::Timestamp;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::proto::services::firewall_metrics_service_server::FirewallMetricsService;
use crate::proto::services::{RealtimeMetric, StreamMetricsRequest};

const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);
const MIN_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Default)]
pub struct MetricsCollector {
    packets_total: AtomicU64,
    bytes_total: AtomicU64,
    drops_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    packets_total: u64,
    bytes_total: u64,
    drops_total: u64,
}

#[derive(Debug, Clone, Copy)]
struct CpuSample {
    idle: u64,
    total: u64,
}

#[derive(Debug, Error)]
enum SystemMetricError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: &'static str,
        source: std::io::Error,
    },
    #[error("missing field in {0}")]
    MissingField(&'static str),
    #[error("invalid integer in {path}: {value}")]
    InvalidInteger {
        path: &'static str,
        value: String,
        source: std::num::ParseIntError,
    },
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_packet(&self, bytes: usize) {
        self.packets_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_total
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub fn observe_drop(&self) {
        self.drops_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_total: self.packets_total.load(Ordering::Relaxed),
            bytes_total: self.bytes_total.load(Ordering::Relaxed),
            drops_total: self.drops_total.load(Ordering::Relaxed),
        }
    }
}

impl MetricsSnapshot {
    pub fn throughput_mbps_since(self, previous: Self, elapsed: Duration) -> f64 {
        let seconds = elapsed.as_secs_f64().max(0.001);
        self.bytes_total.saturating_sub(previous.bytes_total) as f64 * 8.0 / seconds / 1_000_000.0
    }

    pub fn drops_pps_since(self, previous: Self, elapsed: Duration) -> f64 {
        let seconds = elapsed.as_secs_f64().max(0.001);
        self.drops_total.saturating_sub(previous.drops_total) as f64 / seconds
    }
}

pub fn metric_interval(interval_ms: Option<u64>) -> Duration {
    interval_ms
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_INTERVAL)
        .max(MIN_INTERVAL)
}

pub struct SystemMetricsSampler {
    previous_cpu: Option<CpuSample>,
}

impl SystemMetricsSampler {
    pub fn new() -> Self {
        Self { previous_cpu: None }
    }

    pub fn cpu_percent(&mut self) -> f64 {
        match read_cpu_sample() {
            Ok(current) => {
                let value = self
                    .previous_cpu
                    .map(|previous| cpu_percent_between(previous, current))
                    .unwrap_or(0.0);
                self.previous_cpu = Some(current);
                value
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to sample CPU metric");
                0.0
            }
        }
    }

    pub fn memory_percent(&self) -> f64 {
        match read_memory_percent() {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(error = %err, "failed to sample memory metric");
                0.0
            }
        }
    }
}

pub struct MetricsService {
    collector: Arc<MetricsCollector>,
}

impl MetricsService {
    pub fn new(collector: Arc<MetricsCollector>) -> Self {
        Self { collector }
    }
}

#[tonic::async_trait]
impl FirewallMetricsService for MetricsService {
    type StreamMetricsStream = ReceiverStream<Result<RealtimeMetric, Status>>;

    async fn stream_metrics(
        &self,
        request: Request<StreamMetricsRequest>,
    ) -> Result<Response<Self::StreamMetricsStream>, Status> {
        let interval = metric_interval(request.into_inner().interval_ms);
        let collector = Arc::clone(&self.collector);
        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            let mut previous_snapshot = collector.snapshot();
            let mut previous_time = std::time::Instant::now();
            let mut system = SystemMetricsSampler::new();

            loop {
                ticker.tick().await;

                let now = std::time::Instant::now();
                let elapsed = now.duration_since(previous_time);
                let current_snapshot = collector.snapshot();
                let timestamp = SystemTime::now();

                let metrics = [
                    realtime_metric(
                        "throughput",
                        current_snapshot.throughput_mbps_since(previous_snapshot, elapsed),
                        "Mbps",
                        timestamp,
                    ),
                    realtime_metric(
                        "drops",
                        current_snapshot.drops_pps_since(previous_snapshot, elapsed),
                        "pps",
                        timestamp,
                    ),
                    realtime_metric("cpu", system.cpu_percent(), "%", timestamp),
                    realtime_metric("memory", system.memory_percent(), "%", timestamp),
                ];

                previous_snapshot = current_snapshot;
                previous_time = now;

                for metric in metrics {
                    if tx.send(Ok(metric)).await.is_err() {
                        return;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

pub fn realtime_metric(
    name: &str,
    value: f64,
    unit: &str,
    timestamp: SystemTime,
) -> RealtimeMetric {
    RealtimeMetric {
        name: name.to_string(),
        value,
        unit: unit.to_string(),
        timestamp: Some(system_time_to_timestamp(timestamp)),
    }
}

fn system_time_to_timestamp(value: SystemTime) -> Timestamp {
    match value.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => Timestamp {
            seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
        },
        Err(_) => Timestamp {
            seconds: 0,
            nanos: 0,
        },
    }
}

fn cpu_percent_between(previous: CpuSample, current: CpuSample) -> f64 {
    let total_delta = current.total.saturating_sub(previous.total);
    let idle_delta = current.idle.saturating_sub(previous.idle);
    if total_delta == 0 {
        return 0.0;
    }

    ((total_delta.saturating_sub(idle_delta)) as f64 / total_delta as f64 * 100.0).clamp(0.0, 100.0)
}

fn read_cpu_sample() -> Result<CpuSample, SystemMetricError> {
    let path = "/proc/stat";
    let raw =
        fs::read_to_string(path).map_err(|source| SystemMetricError::Read { path, source })?;
    let line = raw
        .lines()
        .next()
        .ok_or(SystemMetricError::MissingField(path))?;
    let mut values = line.split_whitespace().skip(1);

    let user = parse_u64(values.next(), path)?;
    let nice = parse_u64(values.next(), path)?;
    let system = parse_u64(values.next(), path)?;
    let idle = parse_u64(values.next(), path)?;
    let iowait = parse_u64(values.next(), path)?;
    let irq = parse_u64(values.next(), path)?;
    let softirq = parse_u64(values.next(), path)?;
    let steal = values
        .next()
        .map(|value| parse_u64(Some(value), path))
        .transpose()?
        .unwrap_or_default();

    Ok(CpuSample {
        idle: idle.saturating_add(iowait),
        total: user
            .saturating_add(nice)
            .saturating_add(system)
            .saturating_add(idle)
            .saturating_add(iowait)
            .saturating_add(irq)
            .saturating_add(softirq)
            .saturating_add(steal),
    })
}

fn read_memory_percent() -> Result<f64, SystemMetricError> {
    let path = "/proc/meminfo";
    let raw =
        fs::read_to_string(path).map_err(|source| SystemMetricError::Read { path, source })?;
    let mut total = None;
    let mut available = None;

    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("MemTotal:") {
            total = Some(parse_meminfo_value(value, path)?);
        } else if let Some(value) = line.strip_prefix("MemAvailable:") {
            available = Some(parse_meminfo_value(value, path)?);
        }
    }

    let total = total.ok_or(SystemMetricError::MissingField("MemTotal"))?;
    let available = available.ok_or(SystemMetricError::MissingField("MemAvailable"))?;
    if total == 0 {
        return Ok(0.0);
    }

    Ok(((total.saturating_sub(available)) as f64 / total as f64 * 100.0).clamp(0.0, 100.0))
}

fn parse_meminfo_value(value: &str, path: &'static str) -> Result<u64, SystemMetricError> {
    parse_u64(value.split_whitespace().next(), path)
}

fn parse_u64(value: Option<&str>, path: &'static str) -> Result<u64, SystemMetricError> {
    let value = value.ok_or(SystemMetricError::MissingField(path))?;
    value
        .parse()
        .map_err(|source| SystemMetricError::InvalidInteger {
            path,
            value: value.to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    #[test]
    fn collector_tracks_packet_and_drop_deltas() {
        let collector = MetricsCollector::new();
        let previous = collector.snapshot();

        collector.observe_packet(1_000_000);
        collector.observe_packet(500_000);
        collector.observe_drop();

        let current = collector.snapshot();
        let elapsed = Duration::from_secs(1);

        assert_eq!(current.packets_total, 2);
        assert_eq!(current.throughput_mbps_since(previous, elapsed), 12.0);
        assert_eq!(current.drops_pps_since(previous, elapsed), 1.0);
    }

    #[test]
    fn metric_interval_uses_default_and_minimum() {
        assert_eq!(metric_interval(None), DEFAULT_INTERVAL);
        assert_eq!(metric_interval(Some(10)), MIN_INTERVAL);
        assert_eq!(metric_interval(Some(2000)), Duration::from_secs(2));
    }

    #[test]
    fn cpu_percent_is_clamped() {
        let previous = CpuSample {
            idle: 10,
            total: 100,
        };
        let current = CpuSample {
            idle: 20,
            total: 200,
        };

        assert_eq!(cpu_percent_between(previous, current), 90.0);
    }

    #[tokio::test]
    async fn metrics_service_streams_frontend_metric_names() {
        let collector = Arc::new(MetricsCollector::new());
        collector.observe_packet(1_000_000);
        collector.observe_drop();

        let service = MetricsService::new(collector);
        let mut stream = service
            .stream_metrics(Request::new(StreamMetricsRequest {
                interval_ms: Some(250),
            }))
            .await
            .unwrap()
            .into_inner();

        let mut names = Vec::new();
        for _ in 0..4 {
            let metric = tokio::time::timeout(Duration::from_secs(2), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();

            assert!(metric.timestamp.is_some());
            assert!(metric.value >= 0.0);
            names.push((metric.name, metric.unit));
        }

        assert!(names.contains(&("throughput".to_string(), "Mbps".to_string())));
        assert!(names.contains(&("drops".to_string(), "pps".to_string())));
        assert!(names.contains(&("cpu".to_string(), "%".to_string())));
        assert!(names.contains(&("memory".to_string(), "%".to_string())));
    }
}
