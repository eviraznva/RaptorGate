use std::sync::Arc;

use crate::conntrack::entry::{ConntrackEntry, CtStatus};
use crate::conntrack::reassembler::DeliveredChunk;
use crate::conntrack::tuple::Direction;

/// Powód usunięcia entry, dołączany do `CtEvent::Destroy`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyReason {
    /// Reaper wykrył wygaśnięcie expires_at
    Timeout,
    /// Admin wywołał destroy (np. flush, factory reset, query_server delete)
    Manual,
    /// Wstawienie nowego entry zastąpiło stare
    Replaced,
    /// Tabela conntrack jest zamykana
    Shutdown,
    /// L4 lub inna warstwa unieważniła flow (np. policy / inspekcja)
    InvalidatedByStage,
}

/// Anomalia protokołu wykryta podczas update(). Pakiet NIE jest dropowany
/// (verdict pozostaje Accept), ale coś jest podejrzane: out-of-window TCP,
/// ICMP unsolicited, retransmit storm itd
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyKind {
    /// TCP pakiet poza oknem, przepuszczony przez be_liberal=true
    /// Wskazuje na potencjalny spoofing, retransmit storm, lub źle zachowujący się stack
    TcpOutOfWindow,

    /// TCP retransmit (sequence number widziany wcześniej). Częste przy stratach
    /// rzadko alarmujące - subscriber może agregować/throttle'ować
    TcpRetransmit,

    /// TCP flagi naruszają stan FSM (np. SYN po ESTABLISHED, FIN bez ACK w stanie X)
    TcpInvalidFlagsInState,

    /// ICMP error bez matching flow (orphan ICMP)
    IcmpUnsolicited,
}

/// Observer eventów czasów życia modułu conntrack
/// Wszystkie metody MUSZĄ być szybkie, wołane synchronicznie
/// Ciężką pracę należy zlecić na bok przez kanał/kolejkę
pub trait CtObserver: Send + Sync {
    /// Entry właśnie potwierdzone w tabeli (po pierwszym pakiecie lub z expectation)
    /// Sprawdź `entry.has_status(CtStatus::EXPECTED)` żeby odróżnić Related od czystego New
    fn on_new(&self, _entry: &ConntrackEntry) {}

    /// Zmiana statusu lub stanu protokołu. `changed` = bitmapa flag zmienionych
    /// Subscriber filtruje np. `if changed.contains(CtStatus::ASSURED) { ... }`
    fn on_update(&self, _entry: &ConntrackEntry, _changed: CtStatus) {}

    /// Entry usuwane z tabeli. Po tym callbacku NIC się już nie zdarzy dla tego id
    /// Ostatni moment żeby zwolnić per-flow zasoby
    fn on_destroy(&self, _entry: &ConntrackEntry, _reason: DestroyReason) {}

    /// Wykryto anomalię. Pakiet NIE jest dropowany. Wołane synchronicznie
    /// w hot path - implementacja MUSI być szybka
    fn on_anomaly(&self, _entry: &ConntrackEntry, _kind: AnomalyKind) {}

    /// Reassembler emituje ciągły, posortowany po seq fragment streamu TCP
    /// Wołane synchronicznie w hot path. NIE zawiera retransmisji ani out-of-order
    /// dziur — subscriber dostaje tylko nowe bajty w kolejności wysyłki nadawcy
    fn on_payload(&self, _entry: &ConntrackEntry, _dir: Direction, _chunk: &DeliveredChunk) {}
}

#[derive(Default)]
pub struct ObserverRegistry {
    observers: parking_lot::RwLock<Vec<Arc<dyn CtObserver>>>,
}

impl ObserverRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, observer: Arc<dyn CtObserver>) {
        self.observers.write().push(observer);
    }

    pub fn fire_new(&self, entry: &ConntrackEntry) {
        for o in self.snapshot() {
            o.on_new(entry);
        }
    }

    pub fn fire_update(&self, entry: &ConntrackEntry, changed: CtStatus) {
        if changed.is_empty() {
            return;
        }

        for o in self.snapshot() {
            o.on_update(entry, changed);
        }
    }

    pub fn fire_destroy(&self, entry: &ConntrackEntry, reason: DestroyReason) {
        for o in self.snapshot() {
            o.on_destroy(entry, reason);
        }
    }

    pub fn fire_anomaly(&self, entry: &ConntrackEntry, kind: AnomalyKind) {
        for o in self.snapshot() {
            o.on_anomaly(entry, kind);
        }
    }

    pub fn fire_payload(&self, entry: &ConntrackEntry, dir: Direction, chunk: &DeliveredChunk) {
        if chunk.payload.is_empty() {
            return;
        }

        for o in self.snapshot() {
            o.on_payload(entry, dir, chunk);
        }
    }

    pub fn observer_count(&self) -> usize {
        self.observers.read().len()
    }

    fn snapshot(&self) -> Vec<Arc<dyn CtObserver>> {
        self.observers.read().clone()
    }
}