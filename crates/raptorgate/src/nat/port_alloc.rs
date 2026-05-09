use std::sync::Mutex;
use std::net::IpAddr;
use std::collections::HashSet;

use rand::Rng;

use crate::conntrack::tuple::Protocol;
use crate::nat::range::{NatRange, PortStrategy};

const RANDOM_FULLY_MAX_ATTEMPTS: u32 = 128;
const PERSISTENT_WALK_WARN_DISTANCE: u32 = 100;

/// Klucz w pull "co jest zajęte". Tuple (ip, proto, port)
type LeaseKey = (IpAddr, Protocol, u16);

#[derive(Default)]
pub struct PortStore {
    leased: Mutex<HashSet<LeaseKey>>,
}

impl PortStore {
    pub fn new() -> Self { Self::default() }

    /// Próbuje zarezerwować port w `range` dla `proto` na `range.min_ip`
    pub fn alloc(&self, range: &NatRange, proto: Protocol, original_port: u16, seed: u64) -> Option<u16> {
        let mut leased = self.leased.lock().unwrap();

        let ip = range.min_ip;

        // 1. Spróbuj original_port jeśli mieści się w zakresie i jest wolny.
        if original_port >= range.min_port && original_port <= range.max_port && Self::insert_if_free(&mut leased, ip, proto, original_port) {
            return Some(original_port);
        }

        // 2. Zakres jednoportowy (PAT z jawnym portem) — albo original wziął, albo fail.
        if range.min_port == range.max_port {
            return None;
        }

        match range.port_strategy() {
            PortStrategy::Persistent => Self::alloc_persistent(&mut leased, ip, proto, range, seed),
            PortStrategy::Random      => Self::alloc_random(&mut leased, ip, proto, range),
            PortStrategy::RandomFully => Self::alloc_random_fully(&mut leased, ip, proto, range),
        }
    }

    pub fn release(&self, ip: IpAddr, proto: Protocol, port: u16) {
        self.leased.lock().unwrap().remove(&(ip, proto, port));
    }

    pub fn is_leased(&self, ip: IpAddr, proto: Protocol, port: u16) -> bool {
        self.leased.lock().unwrap().contains(&(ip, proto, port))
    }

    fn insert_if_free(leased: &mut HashSet<LeaseKey>, ip: IpAddr, proto: Protocol, port: u16) -> bool {
        leased.insert((ip, proto, port))
    }

    fn alloc_persistent(leased: &mut HashSet<LeaseKey>, ip: IpAddr, proto: Protocol, range: &NatRange, seed: u64) -> Option<u16> {
        let span = range.port_span();

        let offset = (seed % u64::from(span)) as u32;
        let start = u32::from(range.min_port) + offset;

        Self::linear_walk(leased, ip, proto, range, start)
    }

    fn alloc_random(leased: &mut HashSet<LeaseKey>, ip: IpAddr, proto: Protocol, range: &NatRange
    ) -> Option<u16> {
        let span = range.port_span();

        let mut rng = rand::thread_rng();
        rng.gen_range(0..span);
        
        let offset = rng.gen_range(0..span);
        let start = u32::from(range.min_port) + offset;

        Self::linear_walk(leased, ip, proto, range, start)
    }

    fn alloc_random_fully(leased: &mut HashSet<LeaseKey>, ip: IpAddr, proto: Protocol, range: &NatRange) -> Option<u16> {
        let mut rng = rand::thread_rng();
        
        let lo = range.min_port;
        let hi = range.max_port;

        for _ in 0..RANDOM_FULLY_MAX_ATTEMPTS {
            let port = rng.gen_range(lo..=hi);
            
            if Self::insert_if_free(leased, ip, proto, port) {
                return Some(port);
            }
        }
        
        None
    }
    
    fn linear_walk(leased: &mut HashSet<LeaseKey>, ip: IpAddr, proto: Protocol, range: &NatRange, start: u32) -> Option<u16> {
        let span = range.port_span();
        
        let lo = u32::from(range.min_port);
        let hi = u32::from(range.max_port);

        for distance in 0..span {
            let candidate = lo + ((start - lo + distance) % span);
            
            let port = candidate as u16;

            if candidate <= hi && Self::insert_if_free(leased, ip, proto, port) {
                if distance >= PERSISTENT_WALK_WARN_DISTANCE {
                    tracing::warn!(
                          %ip, ?proto, port,
                          walk_distance = distance,
                          "nat persistent walk distance exceeded warn threshold"
                      );
                }
                
                return Some(port);
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr { IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)) }

    #[test]
    fn returns_original_port_when_free_and_in_range() {
        let s = PortStore::new();
        let r = NatRange::single_ip_default(ip());

        let p = s.alloc(&r, Protocol::Tcp, 5000, 0).unwrap();
        
        assert_eq!(p, 5000);
    }

    #[test]
    fn skips_original_when_outside_range() {
        let s = PortStore::new();
        let r = NatRange::single_ip_port_range(ip(), 1024, 1027);

        let p = s.alloc(&r, Protocol::Tcp, 5000, 0).unwrap();
        
        assert!((1024..=1027).contains(&p));
    }

    #[test]
    fn alloc_returns_none_when_range_exhausted() {
        let s = PortStore::new();
        let r = NatRange::single_ip_port_range(ip(), 1024, 1026);

        assert!(s.alloc(&r, Protocol::Tcp, 0, 1).is_some());
        assert!(s.alloc(&r, Protocol::Tcp, 0, 2).is_some());
        assert!(s.alloc(&r, Protocol::Tcp, 0, 3).is_some());
        assert!(s.alloc(&r, Protocol::Tcp, 0, 4).is_none());
    }

    #[test]
    fn release_makes_port_available_again() {
        let s = PortStore::new();
        let r = NatRange::single_ip_port_range(ip(), 1024, 1024);

        let p = s.alloc(&r, Protocol::Tcp, 1024, 0).unwrap();
        
        assert!(s.alloc(&r, Protocol::Tcp, 1024, 0).is_none());

        s.release(ip(), Protocol::Tcp, p);
        
        assert!(s.alloc(&r, Protocol::Tcp, 1024, 0).is_some());
    }

    #[test]
    fn persistent_returns_same_port_for_same_seed() {
        let s = PortStore::new();
        let r = NatRange::single_ip_port_range(ip(), 1024, 65535);

        let p1 = s.alloc(&r, Protocol::Tcp, 0, 0xDEAD_BEEF).unwrap();
        
        s.release(ip(), Protocol::Tcp, p1);

        let p2 = s.alloc(&r, Protocol::Tcp, 0, 0xDEAD_BEEF).unwrap();
        
        assert_eq!(p1, p2);
    }

    #[test]
    fn random_fully_eventually_returns_a_port() {
        let s = PortStore::new();
        let mut r = NatRange::single_ip_default(ip());
        
        r.flags |= crate::nat::range::RangeFlags::PROTO_RANDOM_FULLY;

        let p = s.alloc(&r, Protocol::Tcp, 0, 0).unwrap();
        
        assert!((1024..=65535).contains(&p));
    }

    #[test]
    fn concurrent_alloc_no_double_lease() {
        use std::thread;
        use std::sync::Arc;

        let s = Arc::new(PortStore::new());
        let r = NatRange::single_ip_port_range(ip(), 10000, 10999);

        let handles: Vec<_> = (0..10).map(|t| {
                let s = Arc::clone(&s);
                let r = r.clone();
            
                thread::spawn(move || {
                    let mut got = Vec::new();
                    
                    for i in 0..100 {
                        if let Some(p) = s.alloc(&r, Protocol::Tcp, 0, t * 10000 + i) {
                            got.push(p);
                        }
                    }
                    
                    got
                })
            }).collect();

        let mut all_ports: Vec<u16> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
        all_ports.sort();
        
        let unique = all_ports.len();
        all_ports.dedup();

        assert_eq!(unique, all_ports.len(), "double-lease detected");
    }
}