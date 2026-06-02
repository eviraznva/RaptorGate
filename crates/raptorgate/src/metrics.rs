use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use prost_types::Timestamp;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::conntrack::entry::{ConntrackInterfacePath as EntryInterfacePath, CtInfo};
use crate::conntrack::observer::DestroyReason;
use crate::conntrack::table::{
    Conntrack, ConntrackFlowLifecycle, ConntrackFlowSnapshot, ConntrackNatSnapshot,
    ConntrackSummarySnapshot,
};
use crate::conntrack::tuple::{Direction, FlowTuple, Protocol};
use crate::proto::services::firewall_metrics_service_server::FirewallMetricsService;
use crate::proto::services::{
    ConntrackDestroyReason as ProtoConntrackDestroyReason,
    ConntrackDirection as ProtoConntrackDirection,
    ConntrackFlow as ProtoConntrackFlow,
    ConntrackFlowState as ProtoConntrackFlowState,
    ConntrackFlowTuple as ProtoConntrackFlowTuple,
    ConntrackInterfacePath as ProtoConntrackInterfacePath,
    ConntrackLifecycle as ProtoConntrackLifecycle,
    ConntrackMetricsUpdate,
    ConntrackNatInfo as ProtoConntrackNatInfo,
    ConntrackProtocol as ProtoConntrackProtocol,
    ConntrackSummary,
    RealtimeMetric,
    StreamConntrackMetricsRequest,
    StreamMetricsRequest,
};

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
pub struct CpuSample {
    pub idle: u64,
    pub total: u64,
}

#[derive(Debug, Error)]
pub enum SystemMetricError {
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

pub trait SystemMetricsSource: Send + Sync + Clone + 'static {
    fn read_cpu_sample(&self) -> Result<CpuSample, SystemMetricError>;
    fn read_memory_percent(&self) -> Result<f64, SystemMetricError>;
}

#[derive(Clone, Copy, Default)]
pub struct ProcFsSystemMetricsSource;

impl SystemMetricsSource for ProcFsSystemMetricsSource {
    fn read_cpu_sample(&self) -> Result<CpuSample, SystemMetricError> {
        read_cpu_sample()
    }

    fn read_memory_percent(&self) -> Result<f64, SystemMetricError> {
        read_memory_percent()
    }
}

pub struct SystemMetricsSampler<SystemSource: SystemMetricsSource = ProcFsSystemMetricsSource> {
    previous_cpu: Option<CpuSample>,
    system_source: SystemSource,
}

impl SystemMetricsSampler<ProcFsSystemMetricsSource> {
    pub fn new() -> Self {
        Self::with_system_source(ProcFsSystemMetricsSource)
    }
}

impl<SystemSource: SystemMetricsSource> SystemMetricsSampler<SystemSource> {
    pub fn with_system_source(system_source: SystemSource) -> Self {
        Self {
            previous_cpu: None,
            system_source,
        }
    }

    pub fn cpu_percent(&mut self) -> f64 {
        match self.system_source.read_cpu_sample() {
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
        match self.system_source.read_memory_percent() {
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
    conntrack: Arc<Conntrack>,
}

impl MetricsService {
    pub fn new(collector: Arc<MetricsCollector>, conntrack: Arc<Conntrack>) -> Self {
        Self { collector, conntrack }
    }
}

#[tonic::async_trait]
impl FirewallMetricsService for MetricsService {
    type StreamMetricsStream = ReceiverStream<Result<RealtimeMetric, Status>>;
    type StreamConntrackMetricsStream = ReceiverStream<Result<ConntrackMetricsUpdate, Status>>;

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

    async fn stream_conntrack_metrics(
        &self,
        request: Request<StreamConntrackMetricsRequest>,
    ) -> Result<Response<Self::StreamConntrackMetricsStream>, Status> {
        let request = request.into_inner();
        let interval = metric_interval(request.interval_ms);
        let max_flows = request.max_flows.map(|value| value as usize);
        let include_destroyed = request.include_destroyed.unwrap_or(true);
        let conntrack = Arc::clone(&self.conntrack);
        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;

                let timestamp = SystemTime::now();
                let now = Instant::now();
                let summary = conntrack.metrics().summary();
                let flows = conntrack
                    .metrics()
                    .snapshot_flows(max_flows, include_destroyed)
                    .into_iter()
                    .map(|flow| conntrack_flow_to_proto(flow, now, timestamp))
                    .collect();

                let update = ConntrackMetricsUpdate {
                    timestamp: Some(system_time_to_timestamp(timestamp)),
                    summary: Some(conntrack_summary_to_proto(summary)),
                    flows,
                };

                if tx.send(Ok(update)).await.is_err() {
                    return;
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

fn conntrack_summary_to_proto(summary: ConntrackSummarySnapshot) -> ConntrackSummary {
    ConntrackSummary {
        created: summary.created,
        confirmed: summary.confirmed,
        destroyed: summary.destroyed,
        invalid: summary.invalid,
        drops_table_full: summary.drops_table_full,
        lookups: summary.lookups,
        hits: summary.hits,
        insert_collisions: summary.insert_collisions,
        active_entries: summary.active_entries,
        retained_destroyed_entries: summary.retained_destroyed_entries,
        history_limit: summary.history_limit,
    }
}

fn conntrack_flow_to_proto(
    flow: ConntrackFlowSnapshot,
    now: Instant,
    timestamp: SystemTime,
) -> ProtoConntrackFlow {
    ProtoConntrackFlow {
        id: flow.id,
        lifecycle: conntrack_lifecycle_to_proto(flow.lifecycle) as i32,
        state: conntrack_state_to_proto(flow.state) as i32,
        last_direction: conntrack_direction_to_proto(flow.last_direction) as i32,
        original: Some(flow_tuple_to_proto(flow.original)),
        reply: Some(flow_tuple_to_proto(flow.reply)),
        interfaces: Some(interface_path_to_proto(flow.interfaces)),
        mark: flow.mark,
        status_bits: flow.status_bits,
        bytes_original: flow.bytes_orig,
        bytes_reply: flow.bytes_reply,
        packets_original: flow.packets_orig,
        packets_reply: flow.packets_reply,
        created_at: Some(instant_to_timestamp(flow.created_at, now, timestamp)),
        last_seen_at: Some(instant_to_timestamp(flow.last_seen_at, now, timestamp)),
        expires_at: Some(instant_to_timestamp(flow.expires_at, now, timestamp)),
        destroyed_at: flow.destroyed_at.map(|value| instant_to_timestamp(value, now, timestamp)),
        destroy_reason: conntrack_destroy_reason_to_proto(flow.destroy_reason) as i32,
        nat_info: flow.nat.map(conntrack_nat_to_proto),
    }
}

fn flow_tuple_to_proto(tuple: FlowTuple) -> ProtoConntrackFlowTuple {
    ProtoConntrackFlowTuple {
        src_ip: tuple.src_ip.to_string(),
        src_port: u32::from(tuple.src_port),
        dst_ip: tuple.dst_ip.to_string(),
        dst_port: u32::from(tuple.dst_port),
        protocol: conntrack_protocol_to_proto(tuple.protocol) as i32,
    }
}

fn interface_path_to_proto(path: EntryInterfacePath) -> ProtoConntrackInterfacePath {
    ProtoConntrackInterfacePath {
        original_ingress: path.original_ingress.as_deref().unwrap_or_default().to_string(),
        original_egress: path.original_egress.as_deref().unwrap_or_default().to_string(),
        reply_ingress: path.reply_ingress.as_deref().unwrap_or_default().to_string(),
        reply_egress: path.reply_egress.as_deref().unwrap_or_default().to_string(),
    }
}

fn conntrack_nat_to_proto(nat: ConntrackNatSnapshot) -> ProtoConntrackNatInfo {
    ProtoConntrackNatInfo {
        rule_id: nat.rule_id,
        binding_id: nat.binding_id,
        has_src_nat: nat.has_src_nat,
        has_dst_nat: nat.has_dst_nat,
        allocated_ip: nat.allocated_ip.map(|ip| ip.to_string()),
        allocated_port: nat.allocated_port.map(u32::from),
        src_manip_ip: nat.src_manip.as_ref().map(|manip| manip.ip.to_string()),
        src_manip_port: nat.src_manip.as_ref().and_then(|manip| manip.port.map(u32::from)),
        dst_manip_ip: nat.dst_manip.as_ref().map(|manip| manip.ip.to_string()),
        dst_manip_port: nat.dst_manip.as_ref().and_then(|manip| manip.port.map(u32::from)),
    }
}

fn conntrack_state_to_proto(state: CtInfo) -> ProtoConntrackFlowState {
    match state {
        CtInfo::New => ProtoConntrackFlowState::New,
        CtInfo::Established => ProtoConntrackFlowState::Established,
        CtInfo::Related => ProtoConntrackFlowState::Related,
        CtInfo::Invalid => ProtoConntrackFlowState::Invalid,
    }
}

fn conntrack_lifecycle_to_proto(lifecycle: ConntrackFlowLifecycle) -> ProtoConntrackLifecycle {
    match lifecycle {
        ConntrackFlowLifecycle::Active => ProtoConntrackLifecycle::Active,
        ConntrackFlowLifecycle::Destroyed => ProtoConntrackLifecycle::Destroyed,
    }
}

fn conntrack_direction_to_proto(direction: Option<Direction>) -> ProtoConntrackDirection {
    match direction {
        Some(Direction::Original) => ProtoConntrackDirection::Original,
        Some(Direction::Reply) => ProtoConntrackDirection::Reply,
        None => ProtoConntrackDirection::Unspecified,
    }
}

fn conntrack_protocol_to_proto(protocol: Protocol) -> ProtoConntrackProtocol {
    match protocol {
        Protocol::Tcp => ProtoConntrackProtocol::Tcp,
        Protocol::Udp => ProtoConntrackProtocol::Udp,
        Protocol::Icmp => ProtoConntrackProtocol::Icmp,
        Protocol::IcmpV6 => ProtoConntrackProtocol::Icmpv6,
    }
}

fn conntrack_destroy_reason_to_proto(
    reason: Option<DestroyReason>,
) -> ProtoConntrackDestroyReason {
    match reason {
        Some(DestroyReason::Timeout) => ProtoConntrackDestroyReason::Timeout,
        Some(DestroyReason::Manual) => ProtoConntrackDestroyReason::Manual,
        Some(DestroyReason::Replaced) => ProtoConntrackDestroyReason::Replaced,
        Some(DestroyReason::Shutdown) => ProtoConntrackDestroyReason::Shutdown,
        Some(DestroyReason::InvalidatedByStage) => ProtoConntrackDestroyReason::Manual,
        None => ProtoConntrackDestroyReason::Unspecified,
    }
}

fn instant_to_timestamp(value: Instant, now: Instant, timestamp: SystemTime) -> Timestamp {
    let system_time = if value <= now {
        timestamp
            .checked_sub(now.duration_since(value))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    } else {
        timestamp
            .checked_add(value.duration_since(now))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    };

    system_time_to_timestamp(system_time)
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

    use crate::conntrack::config::ConntrackConfig;
    use crate::conntrack::entry::ConntrackEntry;
    use crate::conntrack::proto::udp::UdpProtoState;
    use crate::conntrack::proto::{ProtoRegistry, ProtoState};
    use crate::conntrack::tuple::{FlowTuple, Protocol};

    fn empty_conntrack() -> Conntrack {
        Conntrack::new(Arc::new(ProtoRegistry::new()), ConntrackConfig::default())
    }

    fn sample_entry() -> Arc<ConntrackEntry> {
        Arc::new(ConntrackEntry::new(
            1,
            FlowTuple::new(
                "10.0.0.1".parse().unwrap(),
                12345,
                "1.1.1.1".parse().unwrap(),
                443,
                Protocol::Udp,
            ),
            ProtoState::Udp(UdpProtoState::default()),
            Duration::from_secs(60),
            0,
        ))
    }

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

        let service = MetricsService::new(collector, Arc::new(empty_conntrack()));
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

    #[tokio::test]
    async fn metrics_service_streams_conntrack_summary_and_flows() {
        let collector = Arc::new(MetricsCollector::new());
        let conntrack = Arc::new(empty_conntrack());
        let entry = sample_entry();

        entry.record_ingress_interface(Direction::Original, "eth0");
        assert!(conntrack.confirm(&entry));

        let service = MetricsService::new(collector, conntrack);
        let mut stream = service
            .stream_conntrack_metrics(Request::new(StreamConntrackMetricsRequest {
                interval_ms: Some(250),
                max_flows: Some(10),
                include_destroyed: Some(true),
            }))
            .await
            .unwrap()
            .into_inner();

        let update = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let summary = update.summary.unwrap();
        let flow = update.flows.first().unwrap();

        assert_eq!(summary.active_entries, 1);
        assert_eq!(flow.id, 1);
        assert_eq!(flow.state, ProtoConntrackFlowState::New as i32);
        assert_eq!(flow.lifecycle, ProtoConntrackLifecycle::Active as i32);
        assert_eq!(flow.original.as_ref().unwrap().src_ip, "10.0.0.1");
        assert_eq!(flow.interfaces.as_ref().unwrap().original_ingress, "eth0");
    }
}
