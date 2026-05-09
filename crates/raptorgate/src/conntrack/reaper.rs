use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinHandle;
use crate::conntrack::table::Conntrack;
use tokio_util::sync::CancellationToken;
use crate::conntrack::entry::ConntrackEntry;
use crate::conntrack::observer::DestroyReason;

/// Jeżeli >"ADAPTIVE_PRESSURE_THRESHOLD" wpisów w jednym przebiegu było wygasłych, oznacza zalew krótkich flow np. skan portów
/// albo SYN flood, wtedy nie czekamy na kolejny gc_interval tylko od razu uruchamiamy kolejny przebieg GC
const ADAPTIVE_PRESSURE_THRESHOLD: f64 = 0.9;

/// Liczba bucketów na którą dzielimy tabelę conntrack. Każdy tick reapera
/// skanuje 1/REAP_BUCKETS wpisów (round-robin po `entry.id % REAP_BUCKETS`).
/// Przy 1M flowów i gc_interval=5s pełny przebieg trwa 5*64=320s.
pub const REAP_BUCKETS: u64 = 64;

/// Maksymalna liczba entry usuwanych w jednym tick'u — bezpiecznik przed
/// długim blokowaniem event loopa przy nagłym wygaśnięciu wielu flowów.
const REAP_BATCH_LIMIT: usize = 4096;

#[derive(Debug, Default, Clone, Copy)]
pub struct ReapStats {
    pub scanned: u64,
    pub expired: u64,
}

impl ReapStats {
    pub fn ratio(&self) -> f64 {
        if self.scanned == 0 {
            0.0
        } else {
            self.expired as f64 / self.scanned as f64
        }
    }
}

pub struct Reaper {
    handle: JoinHandle<()>,
    cancel: CancellationToken,
}

impl Reaper {
    pub fn spawn(ct: Arc<Conntrack>) -> Self {
        let cancel = CancellationToken::new();
        let token = cancel.clone();

        let handle = tokio::spawn(Self::reaper_loop(ct, token));

        Self { handle, cancel }
    }

    pub fn reap_once(ct: &Conntrack, now: Instant) -> ReapStats {
        let mut stats = ReapStats::default();
        
        let bucket = ct.next_reap_bucket();

        let mut victims: Vec<Arc<ConntrackEntry>> = Vec::new();

        for entry in ct.iter_entries() {
            if entry.id % REAP_BUCKETS != bucket { continue; }

            stats.scanned += 1;

            if entry.is_expired(now) {
                victims.push(entry);
                if victims.len() >= REAP_BATCH_LIMIT { break; }
            }
        }

        for v in victims {
            ct.destroy(&v, DestroyReason::Timeout);
            stats.expired += 1;
        }

        ct.expectations().expire(now);

        stats
    }

    pub async fn shutdown(self) {
        self.cancel.cancel();

        let _  = self.handle.await;
    }

    async fn reaper_loop(ct: Arc<Conntrack>, cancel: CancellationToken) {
        loop {
            let gc = ct.config().gc_interval;

            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(gc) => {}
            }

            loop {
                if cancel.is_cancelled() {
                    return;
                }

                let stats = Self::reap_once(&ct, Instant::now());

                if stats.ratio() <= ADAPTIVE_PRESSURE_THRESHOLD {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use etherparse::SlicedPacket;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::conntrack::entry::ConntrackEntry;
    use crate::conntrack::config::ConntrackConfig;
    use crate::conntrack::proto::udp::UdpProtoState;
    use crate::conntrack::tuple::{Direction, FlowTuple, Protocol};
    use crate::conntrack::proto::{
        CtVerdict, NewStateError, NewStateOutcome, ProtoRegistry, ProtoState, ProtocolHandler,
    };

    struct MockHandler;

    impl ProtocolHandler for MockHandler {
        fn proto(&self) -> Protocol { Protocol::Udp }

        fn new_state(&self, _pkt: &SlicedPacket, _dir: Direction, _config: &ConntrackConfig) -> Result<NewStateOutcome, NewStateError> {
            Ok(NewStateOutcome::State(ProtoState::Udp(UdpProtoState::default())))
        }

        fn update(
            &self, _e: &ConntrackEntry, _pkt: &SlicedPacket, _dir: Direction,
            _now: Instant, _config: &ConntrackConfig,
        ) -> CtVerdict {
            CtVerdict::Accept
        }

        fn timeout(&self, _state: &ProtoState, _config: &ConntrackConfig) -> Duration {
            Duration::from_secs(60)
        }
    }

    fn build_ct() -> Arc<Conntrack> {
        let mut registry = ProtoRegistry::new();
        registry.register(Arc::new(MockHandler));

        Arc::new(Conntrack::new(
            Arc::new(registry),
            ConntrackConfig::default(),
        ))
    }
    
    fn drain(ct: &Conntrack) -> ReapStats {
        let mut total = ReapStats::default();

        for _ in 0..REAP_BUCKETS {
            let s = Reaper::reap_once(ct, Instant::now());
            total.scanned += s.scanned;
            total.expired += s.expired;
        }

        total
    }

    fn make_entry(id: u64, port: u16, timeout: Duration) -> Arc<ConntrackEntry> {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            Protocol::Udp,
        );

        Arc::new(ConntrackEntry::new(
            id,
            tuple,
            ProtoState::Udp(UdpProtoState::default()),
            timeout,
            0,
        ))
    }

    #[test]
    fn reap_once_on_empty_table_is_noop() {
        let ct = build_ct();
        let stats = Reaper::reap_once(&ct, Instant::now());

        assert_eq!(stats.scanned, 0);
        assert_eq!(stats.expired, 0);
        assert_eq!(stats.ratio(), 0.0);
    }

    #[test]
    fn reap_once_keeps_fresh_entries() {
        let ct = build_ct();
        let fresh = make_entry(1, 10001, Duration::from_secs(60));

        ct.confirm(&fresh);

        let stats = drain(&ct);

        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.expired, 0);
        assert_eq!(ct.entries_count(), 1);
    }

    #[test]
    fn reap_once_removes_expired_entries() {
        let ct = build_ct();

        let stale = make_entry(1, 10002, Duration::ZERO);
        ct.confirm(&stale);

        let fresh = make_entry(2, 10003, Duration::from_secs(60));
        ct.confirm(&fresh);

        let stats = drain(&ct);

        assert_eq!(stats.scanned, 2);
        assert_eq!(stats.expired, 1);
        assert_eq!(ct.entries_count(), 1);
    }

    #[test]
    fn ratio_handles_division_by_zero() {
        let s = ReapStats::default();

        assert_eq!(s.ratio(), 0.0);
    }

    #[test]
    fn ratio_computes_expired_share() {
        let s = ReapStats { scanned: 10, expired: 9 };

        assert!((s.ratio() - 0.9).abs() < f64::EPSILON);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawned_reaper_runs_and_shuts_down() {
        let ct = build_ct();

        let mut cfg = ConntrackConfig::default();

        cfg.gc_interval = Duration::from_millis(500);
        ct.reload_config(cfg).unwrap();

        // id=0 → bucket 0 — trafia w pierwszy tick reapera (cursor zaczyna od 0).
        let stale = make_entry(0, 10005, Duration::ZERO);
        ct.confirm(&stale);

        assert_eq!(ct.entries_count(), 1);

        let reaper = Reaper::spawn(ct.clone());

        tokio::time::sleep(Duration::from_millis(700)).await;

        reaper.shutdown().await;

        assert_eq!(ct.entries_count(), 0);
    }
}