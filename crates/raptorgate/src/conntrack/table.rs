use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use arc_swap::ArcSwap;
use std::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};
use etherparse::{SlicedPacket, TransportSlice};
use dashmap::{DashMap, mapref::entry::Entry as DashEntry};

use crate::conntrack::reassembler;
use crate::data_plane::packet_context::PacketId;
use crate::conntrack::config::{ConntrackConfig, ConfigError};
use crate::conntrack::tuple::{Direction, FlowTuple, Protocol};
use crate::conntrack::entry::{ConntrackEntry, ConntrackInterfacePath, CtInfo, CtStatus};
use crate::conntrack::expectation::{ExpectationConfig, ExpectationTable};
use crate::conntrack::proto::{CtVerdict, NewStateOutcome, ProtoRegistry, ProtoState};
use crate::conntrack::proto::tcp::TcpConntrack;
use crate::conntrack::observer::{CtObserver, DestroyReason, ObserverRegistry};
use crate::conntrack::tcp_identity::EndpointIdentifier;
use crate::events::{emit, Event, EventKind};
use crate::proto::events as pe;
use crate::rule_tree::types::Port;

#[derive(Debug)]
pub struct ConntrackMetrics {
    pub created: AtomicU64,         // Ile razy stworzyliśmy nowe entry
    pub confirmed: AtomicU64,       // Ile entry potwierdzono (insert do tabeli)
    pub destroyed: AtomicU64,       // Ile entry usunięto
    pub invalid: AtomicU64,         // Ile pakietów verdict=Invalid
    pub drops_table_full: AtomicU64,// Ile odrzuceń bo max_entries
    pub lookups: AtomicU64,         // Wszystkie wyszukania
    pub hits: AtomicU64,            // Hity (znaleziony entry)
    pub insert_collisions: AtomicU64, // confirm() przegrał wyścig z innym pakietem
    flow_registry: parking_lot::RwLock<ConntrackFlowRegistry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackFlowLifecycle {
    Active,
    Destroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConntrackSummarySnapshot {
    pub created: u64,
    pub confirmed: u64,
    pub destroyed: u64,
    pub invalid: u64,
    pub drops_table_full: u64,
    pub lookups: u64,
    pub hits: u64,
    pub insert_collisions: u64,
    pub active_entries: u64,
    pub retained_destroyed_entries: u64,
    pub history_limit: u64,
}

#[derive(Debug, Clone)]
pub struct ConntrackFlowSnapshot {
    pub id: u64,
    pub lifecycle: ConntrackFlowLifecycle,
    pub state: CtInfo,
    pub last_direction: Option<Direction>,
    pub original: FlowTuple,
    pub reply: FlowTuple,
    pub interfaces: ConntrackInterfacePath,
    pub mark: u32,
    pub status_bits: u32,
    pub bytes_orig: u64,
    pub bytes_reply: u64,
    pub packets_orig: u64,
    pub packets_reply: u64,
    pub created_at: Instant,
    pub last_seen_at: Instant,
    pub expires_at: Instant,
    pub destroyed_at: Option<Instant>,
    pub destroy_reason: Option<DestroyReason>,
    pub nat: Option<ConntrackNatSnapshot>,
}

#[derive(Debug, Clone)]
pub struct ConntrackNatSnapshot {
    pub rule_id: String,
    pub binding_id: u64,
    pub has_src_nat: bool,
    pub has_dst_nat: bool,
    pub allocated_ip: Option<IpAddr>,
    pub allocated_port: Option<u16>,
    pub src_manip: Option<ConntrackTupleManipSnapshot>,
    pub dst_manip: Option<ConntrackTupleManipSnapshot>,
}

#[derive(Debug, Clone)]
pub struct ConntrackTupleManipSnapshot {
    pub ip: IpAddr,
    pub port: Option<u16>,
}

#[derive(Debug)]
struct ConntrackFlowRegistry {
    active: HashMap<u64, Weak<ConntrackEntry>>,
    destroyed: VecDeque<ConntrackFlowSnapshot>,
    history_limit: usize,
}

impl Default for ConntrackMetrics {
    fn default() -> Self { Self::new(100_000) }
}

impl ConntrackMetrics {
    pub fn new(flow_history_limit: usize) -> Self {
        Self {
            created: AtomicU64::new(0),
            confirmed: AtomicU64::new(0),
            destroyed: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            drops_table_full: AtomicU64::new(0),
            lookups: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            insert_collisions: AtomicU64::new(0),
            flow_registry: parking_lot::RwLock::new(ConntrackFlowRegistry::new(flow_history_limit)),
        }
    }

    pub fn register_active_flow(&self, entry: &Arc<ConntrackEntry>) {
        self.flow_registry.write().active.insert(entry.id, Arc::downgrade(entry));
    }

    pub fn record_destroyed_flow(&self, entry: &ConntrackEntry, reason: DestroyReason) {
        let mut registry = self.flow_registry.write();
        registry.active.remove(&entry.id);

        if registry.history_limit == 0 {
            return;
        }

        registry.destroyed.push_back(ConntrackFlowSnapshot::destroyed(entry, reason));
        registry.trim_destroyed();
    }

    pub fn set_flow_history_limit(&self, limit: usize) {
        let mut registry = self.flow_registry.write();
        registry.history_limit = limit;
        registry.trim_destroyed();
    }

    pub fn summary(&self) -> ConntrackSummarySnapshot {
        let registry = self.flow_registry.read();

        ConntrackSummarySnapshot {
            created: self.created.load(Ordering::Relaxed),
            confirmed: self.confirmed.load(Ordering::Relaxed),
            destroyed: self.destroyed.load(Ordering::Relaxed),
            invalid: self.invalid.load(Ordering::Relaxed),
            drops_table_full: self.drops_table_full.load(Ordering::Relaxed),
            lookups: self.lookups.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            insert_collisions: self.insert_collisions.load(Ordering::Relaxed),
            active_entries: registry.active.len() as u64,
            retained_destroyed_entries: registry.destroyed.len() as u64,
            history_limit: registry.history_limit as u64,
        }
    }

    pub fn snapshot_flows(
        &self,
        max_flows: Option<usize>,
        include_destroyed: bool,
    ) -> Vec<ConntrackFlowSnapshot> {
        let max_flows = max_flows.unwrap_or(usize::MAX);
        let (active_entries, destroyed_entries) = {
            let mut registry = self.flow_registry.write();
            registry.active.retain(|_, entry| entry.strong_count() > 0);
            let active_entries = registry
                .active
                .values()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            let destroyed_entries = if include_destroyed {
                registry.destroyed.iter().rev().cloned().collect::<Vec<_>>()
            } else {
                Vec::new()
            };

            (active_entries, destroyed_entries)
        };

        let mut flows = Vec::with_capacity(active_entries.len().min(max_flows));

        for entry in active_entries {
            if flows.len() >= max_flows {
                return flows;
            }

            flows.push(ConntrackFlowSnapshot::active(&entry));
        }

        for flow in destroyed_entries {
            if flows.len() >= max_flows {
                break;
            }

            flows.push(flow);
        }

        flows
    }
}

impl ConntrackFlowSnapshot {
    fn active(entry: &ConntrackEntry) -> Self {
        Self::from_entry(entry, ConntrackFlowLifecycle::Active, None, None)
    }

    fn destroyed(entry: &ConntrackEntry, reason: DestroyReason) -> Self {
        Self::from_entry(entry, ConntrackFlowLifecycle::Destroyed, Some(Instant::now()), Some(reason))
    }

    fn from_entry(
        entry: &ConntrackEntry,
        lifecycle: ConntrackFlowLifecycle,
        destroyed_at: Option<Instant>,
        destroy_reason: Option<DestroyReason>,
    ) -> Self {
        let nat = entry.nat.lock().as_ref().map(|nat| ConntrackNatSnapshot {
            rule_id: nat.rule_id.clone(),
            binding_id: nat.binding_id,
            has_src_nat: nat.has_src_manip(),
            has_dst_nat: nat.has_dst_manip(),
            allocated_ip: nat.allocated_ip,
            allocated_port: nat.allocated_port,
            src_manip: nat.src_manip.as_ref().map(|manip| ConntrackTupleManipSnapshot {
                ip: manip.ip,
                port: manip.port,
            }),
            dst_manip: nat.dst_manip.as_ref().map(|manip| ConntrackTupleManipSnapshot {
                ip: manip.ip,
                port: manip.port,
            }),
        });

        Self {
            id: entry.id,
            lifecycle,
            state: entry.ct_info(),
            last_direction: entry.last_direction(),
            original: entry.original,
            reply: entry.reply(),
            interfaces: entry.interface_path(),
            mark: entry.mark.load(Ordering::Relaxed),
            status_bits: entry.status().bits(),
            bytes_orig: entry.bytes_orig.load(Ordering::Relaxed),
            bytes_reply: entry.bytes_reply.load(Ordering::Relaxed),
            packets_orig: entry.packets_orig.load(Ordering::Relaxed),
            packets_reply: entry.packets_reply.load(Ordering::Relaxed),
            created_at: entry.created_at(),
            last_seen_at: entry.last_seen_at(),
            expires_at: entry.expires_at(),
            destroyed_at,
            destroy_reason,
            nat,
        }
    }
}

impl ConntrackFlowRegistry {
    fn new(history_limit: usize) -> Self {
        Self {
            active: HashMap::new(),
            destroyed: VecDeque::new(),
            history_limit,
        }
    }

    fn trim_destroyed(&mut self) {
        while self.destroyed.len() > self.history_limit {
            self.destroyed.pop_front();
        }
    }
}

/// Wartość trzymana pod kluczem `FlowTuple` w `by_tuple`.
///
/// Każdy `ConntrackEntry` jest wstawiany do tabeli pod DWOMA kluczami:
///   - tuple original  → slot { entry, direction: Original }
///   - tuple reply     → slot { entry, direction: Reply }
///
/// Dzięki temu jeden lookup po `FlowTuple` z pakietu od razu mówi
/// czy to ruch original (od inicjatora) czy reply (od peera).
#[derive(Clone, Debug)]
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

fn tcp_conntrack_to_pe_state(s: TcpConntrack) -> pe::TcpSessionState {
    match s {
        TcpConntrack::None => pe::TcpSessionState::None,
        TcpConntrack::SynSent => pe::TcpSessionState::SynSent,
        TcpConntrack::SynRecv => pe::TcpSessionState::SynRecv,
        TcpConntrack::Established => pe::TcpSessionState::Established,
        TcpConntrack::FinWait => pe::TcpSessionState::FinWait,
        TcpConntrack::CloseWait => pe::TcpSessionState::CloseWait,
        TcpConntrack::LastAck => pe::TcpSessionState::LastAck,
        TcpConntrack::TimeWait => pe::TcpSessionState::TimeWait,
        TcpConntrack::Close => pe::TcpSessionState::Close,
        TcpConntrack::SynSent2 => pe::TcpSessionState::SynSent2,
    }
}

fn ct_direction_to_pe(d: Direction) -> pe::ConntrackPacketDirection {
    match d {
        Direction::Original => pe::ConntrackPacketDirection::Original,
        Direction::Reply => pe::ConntrackPacketDirection::Reply,
    }
}

fn original_tuple_endpoints(orig: &FlowTuple) -> (EndpointIdentifier, EndpointIdentifier) {
    (
        EndpointIdentifier {
            ip: orig.src_ip,
            port: Port::from(orig.src_port),
        },
        EndpointIdentifier {
            ip: orig.dst_ip,
            port: Port::from(orig.dst_port),
        },
    )
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
        let flow_history_max_entries = config.flow_history_max_entries as usize;

        Self {
            by_tuple: DashMap::with_capacity(cap),
            expectations: Arc::new(ExpectationTable::new(ExpectationConfig::default())),
            proto,
            observers: Arc::new(ObserverRegistry::default()),
            config: ArcSwap::from_pointee(config),
            metrics: ConntrackMetrics::new(flow_history_max_entries),
            next_id: AtomicU64::new(1),
            reap_cursor: AtomicU64::new(0),
        }
    }

    pub fn flush_deferred_payload_observers(&self, entry: &Arc<ConntrackEntry>) {
        if let Some(chunk) = entry.deferred_first_payload.lock().take() {
            self.observers.fire_payload(entry, Direction::Original, &chunk);
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

    pub fn process(&self, pkt: &SlicedPacket, zone: u16, packet_id: PacketId) -> ProcessOutcome {
        let Some(mut tuple) = FlowTuple::from_sliced(pkt) else {
            self.metrics.invalid.fetch_add(1, Ordering::Relaxed);
            return ProcessOutcome::Invalid;
        };
        
        tuple.zone = zone;

        let now = Instant::now();
        let config = self.config.load();

        match self.lookup(&tuple) {
            LookupResult::Found { entry, direction } => {
                self.update_existing(&entry, pkt, direction, now, &config, packet_id)
            },

            LookupResult::NotFound => {
                self.create_new(tuple, pkt, zone, now, &config, packet_id)
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
        self.metrics.register_active_flow(entry);

        self.observers.fire_new(entry);

        true
    }

    pub fn destroy(&self, entry: &Arc<ConntrackEntry>, reason: DestroyReason) {
        if entry.has_status(CtStatus::DYING) {
            return;
        }

        entry.set_status(CtStatus::DYING);
        self.metrics.record_destroyed_flow(entry, reason);

        if entry.has_status(CtStatus::CONFIRMED) {
            self.by_tuple.remove(&entry.original);
            self.by_tuple.remove(&entry.reply());
        }

        self.expectations.remove_for_parent(entry.id);
        
        self.observers.fire_destroy(entry, reason);
        // tracing::trace!(entries=?self.by_tuple, "conntrack entries on destroy");

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
        self.observers.register(Arc::clone(&observer));

        for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp, Protocol::IcmpV6] {
            if let Some(handler) = self.proto.get(proto) {
                handler.register_observer(Arc::clone(&observer));
            }
        }
    }

    pub fn expectations(&self) -> &Arc<ExpectationTable> {
        &self.expectations
    }
    
    pub fn reload_config(&self, config: ConntrackConfig) -> Result<(), ConfigError> {
        config.validate()?;
        let flow_history_max_entries = config.flow_history_max_entries as usize;

        self.config.store(Arc::new(config));
        self.metrics.set_flow_history_limit(flow_history_max_entries);

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

    pub fn destroy_by_id(&self, id: u64, reason: DestroyReason) -> bool {
        let Some(entry) = self.find_by_id(id) else {
            return false;
        };

        self.destroy(&entry, reason);
        true
    }

    fn create_new(
        &self,
        tuple: FlowTuple,
        pkt: &SlicedPacket,
        zone: u16,
        _now: Instant,
        config: &ConntrackConfig,
        packet_id: PacketId,
    ) -> ProcessOutcome {
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
                            packet_id,
                            payload,
                        );
                        
                        drop(reass);
                        
                        for chunk in chunks {
                            self.observers.fire_payload(&entry, Direction::Original, &chunk);
                        }
                    }
                } else {
                    *entry.deferred_first_payload.lock() = Some(reassembler::DeliveredChunk {
                        packet_id,
                        payload: payload.to_vec(),
                        tcp_payload_start_seq: 0,
                    });
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

    fn update_existing(
        &self,
        entry: &Arc<ConntrackEntry>,
        pkt: &SlicedPacket,
        direction: Direction,
        now: Instant,
        config: &ConntrackConfig,
        packet_id: PacketId,
    ) -> ProcessOutcome {
        let proto = entry.original.protocol;

        let Some(handler) = self.proto.get(proto) else {
            return ProcessOutcome::Invalid;
        };

        let prev_tcp = if proto == Protocol::Tcp {
            match &*entry.proto_state.lock() {
                ProtoState::Tcp(t) => Some(t.state),
                _ => None,
            }
        } else {
            None
        };

        let verdict = handler.update(entry, pkt, direction, now, config, packet_id);

        match verdict {
            CtVerdict::Accept => {
                if let Some(prev) = prev_tcp {
                    let new_tcp = match &*entry.proto_state.lock() {
                        ProtoState::Tcp(t) => Some(t.state),
                        _ => None,
                    };

                    if let Some(new) = new_tcp {
                        if prev != new {
                            let (src, dst) = original_tuple_endpoints(&entry.original);

                            emit(Event::new(EventKind::TcpSessionSubstateChanged {
                                flow_id: entry.id,
                                src,
                                dst,
                                packet_direction: ct_direction_to_pe(direction),
                                previous_state: tcp_conntrack_to_pe_state(prev),
                                new_state: tcp_conntrack_to_pe_state(new),
                            }));
                        }
                    }
                }

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
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    use crate::conntrack::tuple::Protocol;
    use crate::conntrack::observer::CtObserver;
    use crate::conntrack::proto::udp::UdpProtoState;
    use crate::conntrack::proto::{NewStateError, NewStateOutcome, ProtoState, ProtocolHandler};

    struct MockHandler {
        proto: Protocol,
        verdict: Mutex<CtVerdict>,
        timeout: Duration,
        new_state_ok: bool,
        register_count: AtomicUsize,
    }

    impl MockHandler {
        fn new(proto: Protocol) -> Self {
            Self {
                proto,
                verdict: Mutex::new(CtVerdict::Accept),
                timeout: Duration::from_secs(60),
                new_state_ok: true,
                register_count: AtomicUsize::new(0),
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
            _packet_id: crate::data_plane::packet_context::PacketId,
        ) -> CtVerdict {
            *self.verdict.lock()
        }

        fn timeout(&self, _state: &ProtoState, _config: &ConntrackConfig) -> Duration {
            self.timeout
        }

        fn register_observer(&self, _observer: Arc<dyn CtObserver>) {
            self.register_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn build_ct() -> (Conntrack, Arc<MockHandler>) {
        build_ct_with_config(ConntrackConfig::default())
    }

    fn build_ct_with_config(config: ConntrackConfig) -> (Conntrack, Arc<MockHandler>) {
        let handler = Arc::new(MockHandler::new(Protocol::Udp));

        let mut registry = ProtoRegistry::new();
        registry.register(handler.clone());

        let ct = Conntrack::new(Arc::new(registry), config);

        (ct, handler)
    }

    fn build_tcp_ct() -> (Conntrack, Arc<MockHandler>) {
        build_tcp_ct_with_config(ConntrackConfig::default())
    }

    fn build_tcp_ct_with_config(config: ConntrackConfig) -> (Conntrack, Arc<MockHandler>) {
        let handler = Arc::new(MockHandler::new(Protocol::Tcp));

        let mut registry = ProtoRegistry::new();
        registry.register(handler.clone());

        let ct = Conntrack::new(Arc::new(registry), config);

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
    fn register_observer_fanouts_to_tcp_handler() {
        let (ct, handler) = build_tcp_ct();

        struct DummyObserver;

        impl CtObserver for DummyObserver {}

        ct.register_observer(Arc::new(DummyObserver));

        assert_eq!(handler.register_count.load(Ordering::Relaxed), 1);
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
    fn destroy_by_id_removes_confirmed_entry() {
        let (ct, _h) = build_ct();
        let entry = make_entry(&ct, tuple_a());
        assert!(ct.confirm(&entry));
        let id = entry.id;
        assert!(ct.destroy_by_id(id, DestroyReason::InvalidatedByStage));
        assert_eq!(ct.entries_count(), 0);
        assert!(!ct.destroy_by_id(id, DestroyReason::Manual));
    }

    #[test]
    fn metrics_snapshots_active_and_destroyed_flows() {
        let (ct, _h) = build_ct();
        let entry = make_entry(&ct, tuple_a());

        entry.record_ingress_interface(Direction::Original, "eth0");
        assert!(ct.confirm(&entry));

        let active = ct.metrics().snapshot_flows(None, true);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, entry.id);
        assert_eq!(active[0].lifecycle, ConntrackFlowLifecycle::Active);
        assert_eq!(active[0].interfaces.original_ingress.as_deref(), Some("eth0"));

        ct.destroy(&entry, DestroyReason::Timeout);

        let destroyed = ct.metrics().snapshot_flows(None, true);
        assert_eq!(destroyed.len(), 1);
        assert_eq!(destroyed[0].id, entry.id);
        assert_eq!(destroyed[0].lifecycle, ConntrackFlowLifecycle::Destroyed);
        assert_eq!(destroyed[0].destroy_reason, Some(DestroyReason::Timeout));
        assert_eq!(ct.metrics().summary().retained_destroyed_entries, 1);
    }

    #[test]
    fn metrics_trims_destroyed_flow_history() {
        let mut config = ConntrackConfig::default();
        config.flow_history_max_entries = 1;
        let (ct, _h) = build_ct_with_config(config);

        let first = make_entry(&ct, tuple_a());
        let second = make_entry(&ct, FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            10001,
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            53,
            Protocol::Udp,
        ));

        assert!(ct.confirm(&first));
        ct.destroy(&first, DestroyReason::Manual);
        assert!(ct.confirm(&second));
        ct.destroy(&second, DestroyReason::Timeout);

        let flows = ct.metrics().snapshot_flows(None, true);

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].id, second.id);
        assert_eq!(flows[0].destroy_reason, Some(DestroyReason::Timeout));
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
