use bitflags::bitflags;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};

use crate::conntrack::proto::ProtoState;
use crate::conntrack::reassembler::ReassemblyState;
use crate::conntrack::tuple::{Direction, FlowTuple};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CtStatus: u32 {
        const EXPECTED      = 1 << 0;  // Entry został stworzony z expectation
        const SEEN_REPLY    = 1 << 1;  // Zaobserwowano ruch w przeciwnym kierunku (np. odpowiedź na zapytanie), flow jest dwukierunkowy
        const ASSURED       = 1 << 2;  // Flow jest "assured", czyli został potwierdzony przez ruch w obu kierunkach, co oznacza, że jest stabilny i można go bezpiecznie używać do przekazywania ruchu.
        const CONFIRMED     = 1 << 3;  // Entry jest w głównej tabeli. Niepotwierdzone entry można usunąć bez czyszczenia
        const SRC_NAT       = 1 << 4;  // Nat ma być zastosowany do ruchu wychodzącego (source NAT)
        const DST_NAT       = 1 << 5;  // Nat ma być zastosowany od ruchu przychodzącego (destination NAT)
        const SRC_NAT_DONE  = 1 << 6;  // Nat jest już zrobiony na tym pakiecie
        const DST_NAT_DONE  = 1 << 7;  // Nat jest już zrobiony na tym pakiecie
        const DYING         = 1 << 8;  // Entry oznaczone do usunięcia
        const FIXED_TIMEOUT = 1 << 9;  // Timeout został ustawiony manualnie np. przez panel admina, nie ruszać go w maszynie stanów
        const HELPER        = 1 << 10; // Do entry przypisano helper np. dla Ftp Alg
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtInfo {
    New,          // Pierwszy pakiet danego flow, entry właśnie został stworzony, brak SEEN_REPLY
    Established,  // Flow już istnieje, widzieliśmy pakiety w obu kierunkach
    Related,      // Flow jest powiązany z innym flow, np. FTP data connection jest related do FTP control connection
    Invalid,      // Pakiet nie pasuje do żadnego flow ani nie może być NEW np. ACK bez wcześniejszego SYN
}

#[derive(Debug, Clone)]
pub struct NatTransform {
    pub rule_id: String,
    pub binding_id: u64,
    pub allocated_port: Option<u16>,
}

#[derive(Debug)]
pub struct ConntrackEntry {
    pub id: u64,

    pub original: FlowTuple,
    pub reply: parking_lot::Mutex<FlowTuple>,

    pub proto_state: parking_lot::Mutex<ProtoState>,
    pub nat: parking_lot::Mutex<Option<NatTransform>>,
    pub reassembly: parking_lot::Mutex<ReassemblyState>,

    pub bytes_orig: AtomicU64,
    pub bytes_reply: AtomicU64,
    pub packets_orig: AtomicU64,
    pub packets_reply: AtomicU64,

    pub zone: u16,
    pub mark: AtomicU32,

    status: AtomicU32,

    created_at: Instant,
    last_seen_at: parking_lot::Mutex<Instant>,
    expires_at: parking_lot::Mutex<Instant>,
}

impl ConntrackEntry {
    pub fn new(id: u64, mut original: FlowTuple, proto_state: ProtoState, timeout: Duration, zone: u16) -> Self {
        let now = Instant::now();

        original.zone = zone;

        Self {
            id,
            original,
            reply: parking_lot::Mutex::new(original.invert()),
            proto_state: parking_lot::Mutex::new(proto_state),
            nat: parking_lot::Mutex::new(None),
            reassembly: parking_lot::Mutex::new(ReassemblyState::default()),
            bytes_orig: AtomicU64::new(0),
            bytes_reply: AtomicU64::new(0),
            packets_orig: AtomicU64::new(0),
            packets_reply: AtomicU64::new(0),
            zone,
            mark: AtomicU32::new(0),
            status: AtomicU32::new(0),
            created_at: now,
            last_seen_at: parking_lot::Mutex::new(now),
            expires_at: parking_lot::Mutex::new(now + timeout),
        }
    }

    pub fn status(&self) -> CtStatus {
        let bits = self.status.load(Ordering::Acquire);

        CtStatus::from_bits_truncate(bits)
    }

    pub fn set_status(&self, flag: CtStatus) {
        self.status.fetch_or(flag.bits(), Ordering::AcqRel);
    }

    pub fn clear_status(&self, flag: CtStatus) {
        self.status.fetch_and(!flag.bits(), Ordering::AcqRel);
    }

    pub fn has_status(&self, flag: CtStatus) -> bool {
        self.status().contains(flag)
    }

    pub fn touch(&self, now: Instant, timeout: Duration) {
        if self.has_status(CtStatus::FIXED_TIMEOUT) {
            *self.last_seen_at.lock() = now;
            return;
        }

        *self.last_seen_at.lock() = now;
        *self.expires_at.lock() = now + timeout;
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now >= *self.expires_at.lock()
    }

    pub fn last_seen_at(&self) -> Instant { *self.last_seen_at.lock() }

    pub fn expires_at(&self) -> Instant { *self.expires_at.lock() }

    pub fn created_at(&self) -> Instant { self.created_at }

    pub fn set_reply_tuple(&self, reply: FlowTuple) { *self.reply.lock() = reply; }

    pub fn reply(&self) -> FlowTuple { *self.reply.lock() }

    pub fn record_packet(&self, dir: Direction, bytes: u64) {
        match dir {
            Direction::Original => {
                self.packets_orig.fetch_add(1, Ordering::Relaxed);
                self.bytes_orig.fetch_add(bytes, Ordering::Relaxed);
            },

            Direction::Reply => {
                self.packets_reply.fetch_add(1, Ordering::Relaxed);
                self.bytes_reply.fetch_add(bytes, Ordering::Relaxed);
                self.set_status(CtStatus::SEEN_REPLY);
            },
        }
    }

    pub fn ct_info(&self) -> CtInfo {
        let status = self.status();

        if status.contains(CtStatus::EXPECTED) {
            CtInfo::Related
        } else if status.contains(CtStatus::SEEN_REPLY) {
            CtInfo::Established
        } else {
            CtInfo::New
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::conntrack::tuple::Protocol;
    use crate::conntrack::proto::udp::UdpProtoState;

    fn sample_tuple() -> FlowTuple {
        FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            Protocol::Udp,
        )
    }

    fn entry() -> ConntrackEntry {
        ConntrackEntry::new(
            1,
            sample_tuple(),
            ProtoState::Udp(UdpProtoState::default()),
            Duration::from_secs(30),
            0,
        )
    }

    #[test]
    fn new_entry_starts_as_new() {
        let e = entry();

        assert_eq!(e.ct_info(), CtInfo::New);
        assert!(!e.has_status(CtStatus::SEEN_REPLY));
        assert!(!e.has_status(CtStatus::CONFIRMED));
    }

    #[test]
    fn record_reply_sets_established() {
        let e = entry();
        e.record_packet(Direction::Reply, 100);

        assert_eq!(e.ct_info(), CtInfo::Established);
        assert!(e.has_status(CtStatus::SEEN_REPLY));
        assert_eq!(e.packets_reply.load(Ordering::Relaxed), 1);
        assert_eq!(e.bytes_reply.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn touch_extends_expiry() {
        let e = entry();
        let initial_expiry = e.expires_at();

        std::thread::sleep(Duration::from_millis(5));

        e.touch(Instant::now(), Duration::from_secs(60));

        assert!(e.expires_at() > initial_expiry);
    }

    #[test]
    fn fixed_timeout_blocks_touch_extension() {
        let e = entry();

        e.set_status(CtStatus::FIXED_TIMEOUT);

        let frozen = e.expires_at();

        std::thread::sleep(Duration::from_millis(5));

        e.touch(Instant::now(), Duration::from_secs(60));

        assert_eq!(e.expires_at(), frozen);
    }

    #[test]
    fn status_round_trip() {
        let e = entry();

        e.set_status(CtStatus::CONFIRMED | CtStatus::SRC_NAT);

        assert!(e.has_status(CtStatus::CONFIRMED));
        assert!(e.has_status(CtStatus::SRC_NAT));

        e.clear_status(CtStatus::CONFIRMED);

        assert!(!e.has_status(CtStatus::CONFIRMED));
        assert!(e.has_status(CtStatus::SRC_NAT));
    }

    #[test]
    fn expected_yields_related() {
        let e = entry();
        e.set_status(CtStatus::EXPECTED);

        assert_eq!(e.ct_info(), CtInfo::Related);
    }
}