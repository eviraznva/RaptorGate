use std::sync::Arc;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use arc_swap::ArcSwap;
use derive_more::Display;

use crate::conntrack::entry::NatTransform;
use crate::conntrack::tuple::{FlowTuple, Protocol};

/// Krotka oczekiwanego flow z możliwością użycia wildcardów.
///
/// Wildcardy (`None`) są typowe dla helperów, które znają jedną stronę flow,
/// ale nie drugą. Przykład FTP active: klient ogłasza serwerowi "połącz się
/// do mnie na 1.2.3.4:5678" - więc oczekujemy pakietu z dst=(1.2.3.4, 5678),
/// ale src to serwer FTP. Znamy jego IP (`parent.dst_ip`), natomiast src_port
/// serwera może być 20 (klasycznie) albo krótkotrwały w nowoczesnych
/// implementacjach, więc `src_port = None`
///
/// `dst_ip` i `dst_port` są zawsze konkretne - to one są kluczem hash
/// w indeksie `by_dst`. Bez tego musielibyśmy przeszukiwać liniowo całą tabelę
/// expectation dla każdego nowego pakietu
#[derive(Debug, Clone)]
pub struct ExpectationTuple {
    pub src_ip: Option<IpAddr>,    // None = dowolny adres
    pub src_port: Option<u16>,     // None = dowolny port
    pub dst_ip: IpAddr,            // ZAWSZE konkretne (klucz dla `by_dst`)
    pub dst_port: u16,             // ZAWSZE konkretne (klucz dla `by_dst`)
    pub protocol: Protocol,
}

impl ExpectationTuple {
    pub fn matches(&self, tuple: &FlowTuple) -> bool {
        if self.protocol != tuple.protocol { return false; }

        if self.dst_ip != tuple.dst_ip { return false; }

        if self.dst_port != tuple.dst_port { return false; }

        if let Some(ip) = self.src_ip {
            if ip != tuple.src_ip { return false; }
        }

        if let Some(port) = self.src_port {
            if port != tuple.src_port { return false; }
        }

        true
    }

    pub fn dst_key(&self) -> (IpAddr, u16, Protocol) {
        (self.dst_ip, self.dst_port, self.protocol)
    }
}

#[derive(Display, Debug, Clone, PartialEq, Eq)]
pub enum ExpectError {
    GlobalLimit,
    HelperLimit { helper: &'static str },
    Duplicate,
}

/// Pojedyncze "Expectation" ustanowione przez helper (FTP).
#[derive(Debug)]
pub struct Expectation {
    pub id: u64,
    pub parent_id: u64,
    pub helper: &'static str,
    pub tuple: ExpectationTuple,
    pub zone: u16,
    pub expires_at: Instant,
    pub nat_hint: Option<NatTransform>,
}

#[derive(Debug, Clone)]
pub struct ExpectationConfig {
    pub max_total: u32,
    pub max_per_helper: u32,
    pub default_timeout: Duration,
}

impl Default for ExpectationConfig {
    fn default() -> Self {
        Self {
            max_total: 4096,
            max_per_helper: 256,
            default_timeout: Duration::from_secs(300),
        }
    }
}

pub struct ExpectationTable {
    by_id: DashMap<u64, Arc<Expectation>>,
    by_parent: DashMap<u64, Vec<u64>>,
    by_dst: DashMap<(IpAddr, u16, Protocol), Vec<u64>>,
    per_helper_count: DashMap<&'static str, u32>,
    next_id: AtomicU64,
    config: ArcSwap<ExpectationConfig>,
    insert_lock: parking_lot::Mutex<()>,
}

impl ExpectationTable {
    pub fn new(config: ExpectationConfig) -> Self {
        Self {
            by_id: DashMap::new(),
            by_parent: DashMap::new(),
            by_dst: DashMap::new(),
            per_helper_count: DashMap::new(),
            next_id: AtomicU64::new(1),
            config: ArcSwap::from_pointee(config),
            insert_lock: parking_lot::Mutex::new(()),
        }
    }

    pub fn insert(&self, mut exp: Expectation) -> Result<u64, ExpectError> {
        let _guard = self.insert_lock.lock();

        let cfg = self.config.load();

        // Limit globalny.
        if self.by_id.len() as u32 >= cfg.max_total {
            return Err(ExpectError::GlobalLimit);
        }

        // Limit per-helper.
        let current = self.count_for_helper(exp.helper);

        if current >= cfg.max_per_helper {
            return Err(ExpectError::HelperLimit { helper: exp.helper });
        }

        // Duplicate check: czy już mamy expectation z dokładnie tym samym tuple+zone.
        let dst_key = exp.tuple.dst_key();

        if let Some(bucket) = self.by_dst.get(&dst_key) {
            for &existing_id in bucket.iter() {
                if let Some(existing) = self.by_id.get(&existing_id) {
                    if existing.zone == exp.zone && Self::tuples_equal(&existing.tuple, &exp.tuple) {
                        return Err(ExpectError::Duplicate);
                    }
                }
            }
        }

        // Przydziel ID i wstaw.
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        exp.id = id;

        let arc_exp = Arc::new(exp);

        // Kolejność: by_id (source of truth) → by_dst (lookup) → by_parent (destroy hook).
        self.by_id.insert(id, arc_exp.clone());
        self.by_dst.entry(dst_key).or_default().push(id);
        self.by_parent.entry(arc_exp.parent_id).or_default().push(id);

        *self.per_helper_count.entry(arc_exp.helper).or_insert(0) += 1;

        Ok(id)
    }

    pub fn find(&self, tuple: &FlowTuple, zone: u16) -> Option<Arc<Expectation>> {
        let dst_key = (tuple.dst_ip, tuple.dst_port, tuple.protocol);

        let bucket = self.by_dst.get(&dst_key)?;

        for &exp_id in bucket.iter() {
            if let Some(exp) = self.by_id.get(&exp_id) {
                if exp.zone == zone && exp.tuple.matches(tuple) {
                    return Some(exp.clone());
                }
            }
        }

        None
    }

    pub fn remove(&self, id: u64) -> Option<Arc<Expectation>> {
        let (_, exp) = self.by_id.remove(&id)?;

        // Wyczyść by_dst.
        let dst_key = exp.tuple.dst_key();

        if let Some(mut bucket) = self.by_dst.get_mut(&dst_key) {
            bucket.retain(|&x| x != id);
        }

        // Wyczyść by_parent.
        if let Some(mut bucket) = self.by_parent.get_mut(&exp.parent_id) {
            bucket.retain(|&x| x != id);
        }

        // Decrement per-helper count.
        if let Some(mut count) = self.per_helper_count.get_mut(exp.helper) {
            *count = count.saturating_sub(1);
        }

        Some(exp)
    }

    /// Usuwa wszystkie expectations ustanowione przez parent ct
    pub fn remove_for_parent(&self, parent_id: u64) -> usize {
        let ids: Vec<u64> = self.by_parent.remove(&parent_id).map(|(_, v)| v).unwrap_or_default();

        let n = ids.len();

        for id in ids {
            self.remove(id);
        }

        n
    }

    /// Czyści przeterminowane expectations.
    pub fn expire(&self, now: Instant) -> usize {
        let expired: Vec<u64> = self.by_id.iter()
            .filter(|kv| now >= kv.value().expires_at)
            .map(|kv| *kv.key()).collect();

        let n = expired.len();

        for id in expired {
            self.remove(id);
        }

        n
    }

    pub fn reload_config(&self, config: ExpectationConfig) {
        self.config.store(Arc::new(config));
    }

    pub fn config(&self) -> arc_swap::Guard<Arc<ExpectationConfig>> {
        self.config.load()
    }

    pub fn count(&self) -> usize {
        self.by_id.len()
    }

    pub fn count_for_helper(&self, helper: &str) -> u32 {
        self.per_helper_count.get(helper).map(|v| *v).unwrap_or(0)
    }

    fn tuples_equal(a: &ExpectationTuple, b: &ExpectationTuple) -> bool {
        a.src_ip == b.src_ip
            && a.src_port == b.src_port
            && a.dst_ip == b.dst_ip
            && a.dst_port == b.dst_port
            && a.protocol == b.protocol
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn flow(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> FlowTuple {
        FlowTuple::new(src_ip, src_port, dst_ip, dst_port, Protocol::Tcp)
    }

    fn expectation(parent_id: u64, dst_ip: IpAddr, dst_port: u16) -> Expectation {
        Expectation {
            id: 0,
            parent_id,
            helper: "ftp",
            tuple: ExpectationTuple {
                src_ip: None,
                src_port: None,
                dst_ip,
                dst_port,
                protocol: Protocol::Tcp,
            },
            zone: 0,
            expires_at: Instant::now() + Duration::from_secs(300),
            nat_hint: None,
        }
    }

    #[test]
    fn insert_and_find_match() {
        let table = ExpectationTable::new(ExpectationConfig::default());

        let exp = expectation(1, ip(192, 168, 1, 100), 5678);
        let id = table.insert(exp).unwrap();

        // Pakiet z dowolnego src do oczekiwanego dst → match.
        let pkt = flow(ip(10, 0, 0, 5), 20, ip(192, 168, 1, 100), 5678);
        let found = table.find(&pkt, 0).unwrap();

        assert_eq!(found.id, id);
        assert_eq!(found.parent_id, 1);
    }

    #[test]
    fn find_returns_none_for_wrong_dst() {
        let table = ExpectationTable::new(ExpectationConfig::default());
        table.insert(expectation(1, ip(192, 168, 1, 100), 5678)).unwrap();

        // Inny dst_port - nie matchuje (dst_port jest non-wildcard).
        let pkt = flow(ip(10, 0, 0, 5), 20, ip(192, 168, 1, 100), 9999);
        assert!(table.find(&pkt, 0).is_none());
    }

    #[test]
    fn find_respects_zone() {
        let table = ExpectationTable::new(ExpectationConfig::default());
        
        let mut exp = expectation(1, ip(192, 168, 1, 100), 5678);
        exp.zone = 7;
        
        table.insert(exp).unwrap();

        let pkt = flow(ip(10, 0, 0, 5), 20, ip(192, 168, 1, 100), 5678);

        assert!(table.find(&pkt, 0).is_none());   // Inna strefa.
        assert!(table.find(&pkt, 7).is_some());   // Ta sama strefa.
    }

    #[test]
    fn duplicate_insert_rejected() {
        let table = ExpectationTable::new(ExpectationConfig::default());
        table.insert(expectation(1, ip(192, 168, 1, 100), 5678)).unwrap();
        
        let err = table.insert(expectation(2, ip(192, 168, 1, 100), 5678)).unwrap_err();

        assert_eq!(err, ExpectError::Duplicate);
    }

    #[test]
    fn helper_limit_enforced() {
        let mut cfg = ExpectationConfig::default();
        cfg.max_per_helper = 2;
        
        let table = ExpectationTable::new(cfg);
        table.insert(expectation(1, ip(10, 0, 0, 1), 100)).unwrap();
        table.insert(expectation(1, ip(10, 0, 0, 2), 100)).unwrap();
        
        let err = table.insert(expectation(1, ip(10, 0, 0, 3), 100)).unwrap_err();

        assert_eq!(err, ExpectError::HelperLimit { helper: "ftp" });
    }

    #[test]
    fn global_limit_enforced() {
        let mut cfg = ExpectationConfig::default();
        cfg.max_total = 2;
        
        let table = ExpectationTable::new(cfg);
        table.insert(expectation(1, ip(10, 0, 0, 1), 100)).unwrap();
        table.insert(expectation(1, ip(10, 0, 0, 2), 100)).unwrap();
        
        let err = table.insert(expectation(1, ip(10, 0, 0, 3), 100)).unwrap_err();

        assert_eq!(err, ExpectError::GlobalLimit);
    }

    #[test]
    fn remove_clears_all_indexes() {
        let table = ExpectationTable::new(ExpectationConfig::default());
        
        let id = table.insert(expectation(1, ip(10, 0, 0, 1), 100)).unwrap();

        let removed = table.remove(id).unwrap();
        
        assert_eq!(removed.id, id);
        
        let pkt = flow(ip(1, 1, 1, 1), 20, ip(10, 0, 0, 1), 100);
        
        assert!(table.find(&pkt, 0).is_none());
        assert_eq!(table.count(), 0);
        assert_eq!(table.count_for_helper("ftp"), 0);
    }

    #[test]
    fn remove_for_parent_drops_all_children() {
        let table = ExpectationTable::new(ExpectationConfig::default());
        table.insert(expectation(42, ip(10, 0, 0, 1), 100)).unwrap();
        table.insert(expectation(42, ip(10, 0, 0, 2), 200)).unwrap();
        table.insert(expectation(42, ip(10, 0, 0, 3), 300)).unwrap();
        table.insert(expectation(99, ip(10, 0, 0, 4), 400)).unwrap();

        let removed = table.remove_for_parent(42);
        
        assert_eq!(removed, 3);
        assert_eq!(table.count(), 1);
        
        let pkt = flow(ip(1, 1, 1, 1), 20, ip(10, 0, 0, 4), 400);
        
        assert!(table.find(&pkt, 0).is_some());
    }

    #[test]
    fn expire_removes_only_overdue() {
        let table = ExpectationTable::new(ExpectationConfig::default());
        
        let mut fresh = expectation(1, ip(10, 0, 0, 1), 100);
        fresh.expires_at = Instant::now() + Duration::from_secs(60);
        
        table.insert(fresh).unwrap();
        
        let mut stale = expectation(2, ip(10, 0, 0, 2), 200);
        stale.expires_at = Instant::now() - Duration::from_secs(1);
        
        table.insert(stale).unwrap();

        let n = table.expire(Instant::now());

        assert_eq!(n, 1);
        assert_eq!(table.count(), 1);
    }

    #[test]
    fn wildcard_src_matches_any_source() {
        let table = ExpectationTable::new(ExpectationConfig::default());
        table.insert(expectation(1, ip(192, 168, 1, 100), 5678)).unwrap();
        
        for src in [ip(10, 0, 0, 1), ip(172, 16, 0, 5), ip(8, 8, 8, 8)] {
            for port in [20, 12345, 65000] {
                let pkt = flow(src, port, ip(192, 168, 1, 100), 5678);
                assert!(table.find(&pkt, 0).is_some(), "src={:?} port={}", src, port);
            }
        }
    }

    #[test]
    fn non_wildcard_src_filters() {
        let table = ExpectationTable::new(ExpectationConfig::default());

        let mut exp = expectation(1, ip(192, 168, 1, 100), 5678);
        exp.tuple.src_ip = Some(ip(10, 0, 0, 99));
        
        table.insert(exp).unwrap();
        
        let pkt = flow(ip(10, 0, 0, 1), 20, ip(192, 168, 1, 100), 5678);
        
        assert!(table.find(&pkt, 0).is_none());
        
        let pkt2 = flow(ip(10, 0, 0, 99), 20, ip(192, 168, 1, 100), 5678);
        
        assert!(table.find(&pkt2, 0).is_some());
    }
}