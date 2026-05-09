use std::sync::Arc;
use arc_swap::ArcSwap;
use std::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};
use etherparse::{SlicedPacket, TransportSlice};
use dashmap::{DashMap, mapref::entry::Entry as DashEntry};

use crate::conntrack::reassembler;
use crate::conntrack::config::{ConntrackConfig, ConfigError};
use crate::conntrack::tuple::{Direction, FlowTuple, Protocol};
use crate::conntrack::entry::{ConntrackEntry, CtInfo, CtStatus};
use crate::conntrack::expectation::{ExpectationConfig, ExpectationTable};
use crate::conntrack::proto::{CtVerdict, NewStateOutcome, ProtoRegistry};
use crate::conntrack::observer::{CtObserver, DestroyReason, ObserverRegistry};

#[derive(Debug, Default)]
pub struct ConntrackMetrics {
    pub created: AtomicU64,         // Ile razy stworzyliśmy nowe entry
    pub confirmed: AtomicU64,       // Ile entry potwierdzono (insert do tabeli)
    pub destroyed: AtomicU64,       // Ile entry usunięto
    pub invalid: AtomicU64,         // Ile pakietów verdict=Invalid
    pub drops_table_full: AtomicU64,// Ile odrzuceń bo max_entries
    pub lookups: AtomicU64,         // Wszystkie wyszukania
    pub hits: AtomicU64,            // Hity (znaleziony entry)
    pub insert_collisions: AtomicU64, // confirm() przegrał wyścig z innym pakietem
}

/// Wartość trzymana pod kluczem `FlowTuple` w `by_tuple`.
///
/// Każdy `ConntrackEntry` jest wstawiany do tabeli pod DWOMA kluczami:
///   - tuple original  → slot { entry, direction: Original }
///   - tuple reply     → slot { entry, direction: Reply }
///
/// Dzięki temu jeden lookup po `FlowTuple` z pakietu od razu mówi
/// czy to ruch original (od inicjatora) czy reply (od peera).
#[derive(Clone)]
struct TupleSlot {
    entry: Arc<ConntrackEntry>,
    direction: Direction,
}

pub enum LookupResult {
    Found {
        entry: Arc<ConntrackEntry>,
        direction: Direction,
    },
    NotFound,
}

pub enum ProcessOutcome {
    Accept {
        entry: Arc<ConntrackEntry>,
        info: CtInfo,
        direction: Direction,
        is_new: bool, // Czy entry zostało dopiero co stworzone
    },
    Invalid,
    Drop,
    TableFull,
}

pub struct Conntrack {
    by_tuple: DashMap<FlowTuple, TupleSlot>,
    expectations: Arc<ExpectationTable>,
    proto: Arc<ProtoRegistry>,
    observers: Arc<ObserverRegistry>,
    config: ArcSwap<ConntrackConfig>,
    metrics: ConntrackMetrics,
    next_id: AtomicU64,
    reap_cursor: AtomicU64,
}

impl Conntrack {
    pub fn new(proto: Arc<ProtoRegistry>, config: ConntrackConfig) -> Self {
        let cap = config.htable_size as usize;

        Self {
            by_tuple: DashMap::with_capacity(cap),
            expectations: Arc::new(ExpectationTable::new(ExpectationConfig::default())),
            proto,
            observers: Arc::new(ObserverRegistry::default()),
            config: ArcSwap::from_pointee(config),
            metrics: ConntrackMetrics::default(),
            next_id: AtomicU64::new(1),
            reap_cursor: AtomicU64::new(0),
        }
    }

    /// Zwraca następny bucket reapera (round-robin po 1/REAP_BUCKETS tabeli).
    pub fn next_reap_bucket(&self) -> u64 {
        self.reap_cursor.fetch_add(1, Ordering::Relaxed) % crate::conntrack::reaper::REAP_BUCKETS
    }

    pub fn lookup(&self, tuple: &FlowTuple) -> LookupResult {
        self.metrics.lookups.fetch_add(1, Ordering::Relaxed);

        if let Some(slot) = self.by_tuple.get(tuple) {
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);

            return LookupResult::Found {
                entry: slot.entry.clone(),
                direction: slot.direction,
            }
        }

        LookupResult::NotFound
    }

    pub fn process(&self, pkt: &SlicedPacket, zone: u16) -> ProcessOutcome {
        let Some(mut tuple) = FlowTuple::from_sliced(pkt) else {
            self.metrics.invalid.fetch_add(1, Ordering::Relaxed);
            return ProcessOutcome::Invalid;
        };
        
        tuple.zone = zone;

        let now = Instant::now();
        let config = self.config.load();

        match self.lookup(&tuple) {
            LookupResult::Found { entry, direction } => {
                self.update_existing(&entry, pkt, direction, now, &config)
            },
            
            LookupResult::NotFound => {
                self.create_new(tuple, pkt, zone, now, &config)
            }
        }
    }

    pub fn confirm(&self, entry: &Arc<ConntrackEntry>) -> bool {
        if entry.has_status(CtStatus::CONFIRMED) {
            return true;
        }

        let original = entry.original;
        let reply = entry.reply();

        // Krok 1: spróbuj wstawić original.
        match self.by_tuple.entry(original) {
            DashEntry::Occupied(_) => {
                self.metrics.insert_collisions.fetch_add(1, Ordering::Relaxed);
                return false;
            },

            DashEntry::Vacant(slot) => {
                slot.insert(TupleSlot {
                    entry: entry.clone(),
                    direction: Direction::Original,
                });
            },
        }

        // Krok 2: wstaw reply. Jeśli kolizja → rollback original.
        match self.by_tuple.entry(reply) {
            DashEntry::Occupied(_) => {
                self.by_tuple.remove(&original);
                self.metrics.insert_collisions.fetch_add(1, Ordering::Relaxed);

                return false;
            },

            DashEntry::Vacant(slot) => {
                slot.insert(TupleSlot {
                    entry: entry.clone(),
                    direction: Direction::Reply,
                });
            }
        }

        entry.set_status(CtStatus::CONFIRMED);
        self.metrics.confirmed.fetch_add(1, Ordering::Relaxed);

        self.observers.fire_new(entry);

        true
    }

    pub fn destroy(&self, entry: &Arc<ConntrackEntry>, reason: DestroyReason) {
        if entry.has_status(CtStatus::DYING) {
            return;
        }

        entry.set_status(CtStatus::DYING);

        if entry.has_status(CtStatus::CONFIRMED) {
            self.by_tuple.remove(&entry.original);
            self.by_tuple.remove(&entry.reply());
        }

        self.expectations.remove_for_parent(entry.id);
        
        self.observers.fire_destroy(entry, reason);

        self.metrics.destroyed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn flush_zone(&self, zone: u16) -> usize {
        let victims: Vec<Arc<ConntrackEntry>> = self.by_tuple.iter()
            .filter(|kv| {
                kv.value().direction == Direction::Original && kv.value().entry.zone == zone
            }).map(|kv| kv.value().entry.clone())
            .collect();

        let n = victims.len();

        for v in victims {
            self.destroy(&v, DestroyReason::Manual);
        }

        n
    }

    pub fn flush_all(&self) -> usize {
        let victims: Vec<Arc<ConntrackEntry>> = self.iter_entries();

        let n = victims.len();

        for v in victims {
            self.destroy(&v, DestroyReason::Manual);
        }

        n
    }

    pub fn register_observer(&self, observer: Arc<dyn CtObserver>) {
        self.observers.register(observer);
    }

    pub fn expectations(&self) -> &Arc<ExpectationTable> {
        &self.expectations
    }
    
    pub fn reload_config(&self, config: ConntrackConfig) -> Result<(), ConfigError> {
        config.validate()?;
        
        self.config.store(Arc::new(config));
        
        Ok(())
    }

    pub fn config(&self) -> arc_swap::Guard<Arc<ConntrackConfig>> {
        self.config.load()
    }

    pub fn metrics(&self) -> &ConntrackMetrics {
        &self.metrics
    }

    pub fn entries_count(&self) -> usize {
        self.by_tuple.len() / 2
    }

    pub fn iter_entries(&self) -> Vec<Arc<ConntrackEntry>> {
        self.by_tuple.iter().filter(|kv| kv.value().direction == Direction::Original)
            .map(|kv| kv.value().entry.clone())
            .collect()
    }

    pub fn find_by_id(&self, id: u64) -> Option<Arc<ConntrackEntry>> {
        self.by_tuple.iter()
            .find(|kv| kv.value().direction == Direction::Original && kv.value().entry.id == id)
            .map(|kv| kv.value().entry.clone())
    }

    fn create_new(&self, tuple: FlowTuple, pkt: &SlicedPacket, zone: u16, _now: Instant, config: &ConntrackConfig) -> ProcessOutcome {
        if self.entries_count() >= config.max_entries as usize {
            self.metrics.drops_table_full.fetch_add(1, Ordering::Relaxed);

            return ProcessOutcome::TableFull;
        }

        let Some(handler) = self.proto.get(tuple.protocol) else {
            return ProcessOutcome::Invalid;
        };

        let outcome = match handler.new_state(pkt, Direction::Original, config) {
            Ok(o) => o,
            Err(_) => {
                self.metrics.invalid.fetch_add(1, Ordering::Relaxed);
                return ProcessOutcome::Invalid;
            },
        };

        let proto_state = match outcome {
            NewStateOutcome::State(s) => s,

            NewStateOutcome::Related { mut parent_tuple } => {
                // ICMP error niesie embedded packet wskazujący na parent flow.
                // Nie tworzymy nowego entry, tylko podpinamy się jako RELATED.
                parent_tuple.zone = zone;

                return match self.lookup(&parent_tuple) {
                    LookupResult::Found { entry, direction } => {
                        entry.record_packet(direction, Self::packet_payload_len(pkt));

                        ProcessOutcome::Accept {
                            entry,
                            info: CtInfo::Related,
                            direction,
                            is_new: false,
                        }
                    },

                    LookupResult::NotFound => {
                        self.metrics.invalid.fetch_add(1, Ordering::Relaxed);
                        ProcessOutcome::Invalid
                    },
                };
            },
        };

        let timeout = handler.timeout(&proto_state, config);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let expectation = self.expectations.find(&tuple, zone);

        let entry = Arc::new(ConntrackEntry::new(id, tuple, proto_state, timeout, zone));

        if let Some(exp) = expectation {
            entry.set_status(CtStatus::EXPECTED);

            if let Some(nat_hint) = &exp.nat_hint {
                *entry.nat.lock() = Some(nat_hint.clone());
            }
            
            self.expectations.remove(exp.id);
        }
        
        entry.record_packet(Direction::Original, Self::packet_payload_len(pkt));

        self.metrics.created.fetch_add(1, Ordering::Relaxed);

        if let Some(payload) = Self::extract_l4_payload(pkt) {
            if !payload.is_empty() {
                if entry.original.protocol == Protocol::Tcp {
                    if let Some(TransportSlice::Tcp(t)) = pkt.transport.as_ref() {
                        let mut reass = entry.reassembly.lock();
                        
                        let chunks = reassembler::feed(
                            &mut reass.dirs[Direction::Original as usize],
                            &config.reassembly,
                            t.sequence_number(),
                            payload,
                        );
                        
                        drop(reass);
                        
                        for chunk in chunks {
                            self.observers.fire_payload(&entry, Direction::Original, &chunk);
                        }
                    }
                } else {
                    // UDP/ICMP — datagram bezpośrednio.
                    self.observers.fire_payload(&entry, Direction::Original, payload);
                }
            }
        }

        // UWAGA: entry jeszcze NIE jest w tabeli. Pipeline (NAT, policy)
        // może je odrzucić albo zmodyfikować reply tuple. Dopiero
        // ConntrackConfirmStage wywoła confirm() i wstawi do mapy.
        ProcessOutcome::Accept {
            entry,
            info: CtInfo::New,
            direction: Direction::Original,
            is_new: true,
        }
    }

    fn update_existing(&self, entry: &Arc<ConntrackEntry>, pkt: &SlicedPacket, direction: Direction, now: Instant, config: &ConntrackConfig) -> ProcessOutcome {
        let proto = entry.original.protocol;

        let Some(handler) = self.proto.get(proto) else {
            return ProcessOutcome::Invalid;
        };

        let verdict = handler.update(entry, pkt, direction, now, config);

        match verdict {
            CtVerdict::Accept => {
                let prev_status = if self.observers.observer_count() > 0 {
                    Some(entry.status())
                } else {
                    None
                };

                let timeout = handler.timeout(&entry.proto_state.lock(), config);

                entry.touch(now, timeout);
                entry.record_packet(direction, Self::packet_payload_len(pkt));

                if handler.is_assured(&entry.proto_state.lock()) {
                    entry.set_status(CtStatus::ASSURED);
                }

                if let Some(prev) = prev_status {
                    let changed = prev ^ entry.status();

                    self.observers.fire_update(entry, changed);
                }

                ProcessOutcome::Accept {
                    entry: entry.clone(),
                    info: entry.ct_info(),
                    direction,
                    is_new: false,
                }
            },

            CtVerdict::Invalid => {
                self.metrics.invalid.fetch_add(1, Ordering::Relaxed);
                ProcessOutcome::Invalid
            },

            CtVerdict::Drop => ProcessOutcome::Drop,
        }
    }

    fn extract_l4_payload<'a>(pkt: &'a SlicedPacket<'a>) -> Option<&'a [u8]> {
        match pkt.transport.as_ref()? {
            TransportSlice::Tcp(t) => Some(t.payload()),
            TransportSlice::Udp(u) => Some(u.payload()),
            TransportSlice::Icmpv4(i) => Some(i.payload()),
            TransportSlice::Icmpv6(i) => Some(i.payload()),
        }
    }
    
    fn packet_payload_len(pkt: &SlicedPacket) -> u64 {
        let l4 = match pkt.transport.as_ref() {
            Some(TransportSlice::Tcp(t)) => t.payload().len(),
            Some(TransportSlice::Udp(u)) => u.payload().len(),
            Some(TransportSlice::Icmpv4(i)) => i.payload().len(),
            Some(TransportSlice::Icmpv6(i)) => i.payload().len(),
            None => 0,
        };

        l4 as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::time::Duration;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicU32;

    use crate::conntrack::tuple::Protocol;
    use crate::conntrack::proto::udp::UdpProtoState;
    use crate::conntrack::proto::{NewStateError, NewStateOutcome, ProtoState, ProtocolHandler};

    struct MockHandler {
        proto: Protocol,
        verdict: Mutex<CtVerdict>,
        timeout: Duration,
        new_state_ok: bool,
    }

    impl MockHandler {
        fn new(proto: Protocol) -> Self {
            Self {
                proto,
                verdict: Mutex::new(CtVerdict::Accept),
                timeout: Duration::from_secs(60),
                new_state_ok: true,
            }
        }
    }

    impl ProtocolHandler for MockHandler {
        fn proto(&self) -> Protocol { self.proto }

        fn new_state(
            &self,
            _pkt: &SlicedPacket,
            _dir: Direction,
            _config: &ConntrackConfig,
        ) -> Result<NewStateOutcome, NewStateError> {
            if self.new_state_ok {
                Ok(NewStateOutcome::State(ProtoState::Udp(UdpProtoState::default())))
            } else {
                Err(NewStateError::MissingTransport)
            }
        }

        fn update(
            &self,
            _entry: &ConntrackEntry,
            _pkt: &SlicedPacket,
            _dir: Direction,
            _now: Instant,
            _config: &ConntrackConfig,
        ) -> CtVerdict {
            *self.verdict.lock()
        }

        fn timeout(&self, _state: &ProtoState, _config: &ConntrackConfig) -> Duration {
            self.timeout
        }
    }

    fn build_ct() -> (Conntrack, Arc<MockHandler>) {
        let handler = Arc::new(MockHandler::new(Protocol::Udp));

        let mut registry = ProtoRegistry::new();
        registry.register(handler.clone());

        let ct = Conntrack::new(Arc::new(registry), ConntrackConfig::default());

        (ct, handler)
    }

    fn tuple_a() -> FlowTuple {
        FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            10000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            Protocol::Udp,
        )
    }

    fn make_entry(ct: &Conntrack, tuple: FlowTuple) -> Arc<ConntrackEntry> {
        let id = ct.next_id.fetch_add(1, Ordering::Relaxed);

        Arc::new(ConntrackEntry::new(
            id,
            tuple,
            ProtoState::Udp(UdpProtoState::default()),
            Duration::from_secs(60),
            0,
        ))
    }

    #[test]
    fn lookup_miss_returns_not_found() {
        let (ct, _h) = build_ct();

        assert!(matches!(ct.lookup(&tuple_a()), LookupResult::NotFound));
        assert_eq!(ct.metrics.lookups.load(Ordering::Relaxed), 1);
        assert_eq!(ct.metrics.hits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn confirm_inserts_both_directions() {
        let (ct, _h) = build_ct();
        let entry = make_entry(&ct, tuple_a());

        assert!(ct.confirm(&entry));
        assert!(entry.has_status(CtStatus::CONFIRMED));

        let f1 = ct.lookup(&tuple_a());
        let f2 = ct.lookup(&tuple_a().invert());

        assert!(matches!(f1, LookupResult::Found { direction: Direction::Original, .. }));
        assert!(matches!(f2, LookupResult::Found { direction: Direction::Reply, .. }));
        assert_eq!(ct.entries_count(), 1);
    }

    #[test]
    fn confirm_is_idempotent() {
        let (ct, _h) = build_ct();

        let entry = make_entry(&ct, tuple_a());

        assert!(ct.confirm(&entry));
        assert!(ct.confirm(&entry));
        assert_eq!(ct.entries_count(), 1);
    }

    #[test]
    fn confirm_collision_rolls_back() {
        let (ct, _h) = build_ct();

        let e1 = make_entry(&ct, tuple_a());
        let e2 = make_entry(&ct, tuple_a()); // ten sam tuple, inny id

        assert!(ct.confirm(&e1));
        assert!(!ct.confirm(&e2));
        assert_eq!(ct.entries_count(), 1);
        assert_eq!(ct.metrics.insert_collisions.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn flush_all_removes_every_entry() {
        let (ct, _h) = build_ct();

        for port in 10000..10010 {
            let tuple = FlowTuple::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port,
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                53,
                Protocol::Udp,
            );

            let entry = make_entry(&ct, tuple);

            ct.confirm(&entry);
        }

        assert_eq!(ct.entries_count(), 10);

        let n = ct.flush_all();

        assert_eq!(n, 10);
        assert_eq!(ct.entries_count(), 0);
    }

    #[test]
    fn reload_config_swaps_atomically() {
        let (ct, _h) = build_ct();

        let mut new = ConntrackConfig::default();

        new.max_entries = 4096;
        new.htable_size = 1024;

        ct.reload_config(new.clone()).unwrap();

        assert_eq!(ct.config().max_entries, 4096);
    }

    #[test]
    fn iter_entries_returns_unique_per_flow() {
        let (ct, _h) = build_ct();

        let entry = make_entry(&ct, tuple_a());

        ct.confirm(&entry);

        let v = ct.iter_entries();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, entry.id);
    }

    #[test]
    fn observer_receives_full_lifecycle() {
        #[derive(Default)]
        struct Tracker {
            new: AtomicU32,
            destroy: AtomicU32,
            last_reason: Mutex<Option<DestroyReason>>,
        }

        impl CtObserver for Tracker {
            fn on_new(&self, _e: &ConntrackEntry) {
                self.new.fetch_add(1, Ordering::Relaxed);
            }

            fn on_destroy(&self, _e: &ConntrackEntry, reason: DestroyReason) {
                self.destroy.fetch_add(1, Ordering::Relaxed);
                *self.last_reason.lock() = Some(reason);
            }
        }

        let (ct, _h) = build_ct();

        let tracker = Arc::new(Tracker::default());

        ct.register_observer(tracker.clone());

        let entry = make_entry(&ct, tuple_a());

        ct.confirm(&entry);

        assert_eq!(tracker.new.load(Ordering::Relaxed), 1);

        ct.destroy(&entry, DestroyReason::Timeout);

        assert_eq!(tracker.destroy.load(Ordering::Relaxed), 1);
        assert_eq!(*tracker.last_reason.lock(), Some(DestroyReason::Timeout));
    }

    #[test]
    fn observer_does_not_fire_new_on_collision() {
        struct Counter(AtomicU32);

        impl CtObserver for Counter {
            fn on_new(&self, _e: &ConntrackEntry) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let (ct, _h) = build_ct();
        let counter = Arc::new(Counter(AtomicU32::new(0)));

        ct.register_observer(counter.clone());

        let e1 = make_entry(&ct, tuple_a());
        let e2 = make_entry(&ct, tuple_a());

        assert!(ct.confirm(&e1));
        assert!(!ct.confirm(&e2));

        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    }
}