pub mod ftp;

use std::sync::Arc;
use std::collections::HashMap;

use crate::conntrack::table::Conntrack;
use crate::conntrack::entry::ConntrackEntry;
use crate::conntrack::expectation::Expectation;
use crate::conntrack::tuple::{Direction, Protocol};

pub trait Helper: Send + Sync {
    fn name(&self) -> &'static str;

    fn proto(&self) -> Protocol;

    /// Porty, na których helper się aktywuje. FTP = [21], SIP = [5060] itd
    fn ports(&self) -> &'static [u16];

    /// Inspekcja payloadu. Zwraca listę expectations do zainstalowania
    /// Pusty vec jeśli nic nie wykryto.
    fn inspect(&self, entry: &ConntrackEntry, payload: &[u8], dir: Direction) -> Vec<Expectation>;

    fn install_expectations(&self, entry: &ConntrackEntry, payload: &[u8], dir: Direction, conntrack: &Conntrack) {
        for exp in self.inspect(entry, payload, dir) {
            if let Err(e) = conntrack.expectations().insert(exp) {
                tracing::debug!(error = %e, helper = self.name(), "failed to install expectation");
            }
        }
    }
}

#[derive(Default)]
pub struct HelperRegistry {
    by_port: HashMap<(Protocol, u16), Arc<dyn Helper>>,
}

impl HelperRegistry {
    pub fn new() -> Self { Self::default() }

    pub fn register(&mut self, helper: Arc<dyn Helper>) {
        let proto = helper.proto();
        
        for &port in helper.ports() {
            self.by_port.insert((proto, port), helper.clone());
        }
    }

    pub fn lookup(&self, proto: Protocol, port: u16) -> Option<Arc<dyn Helper>> {
        self.by_port.get(&(proto, port)).cloned()
    }

    pub fn len(&self) -> usize { self.by_port.len() }
    
    pub fn is_empty(&self) -> bool { self.by_port.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use crate::conntrack::tuple::Protocol;
    use crate::conntrack::entry::ConntrackEntry;

    struct DummyHelper {
        name: &'static str,
        proto: Protocol,
        ports: &'static [u16],
    }

    impl Helper for DummyHelper {
        fn name(&self) -> &'static str { self.name }
        
        fn proto(&self) -> Protocol { self.proto }
        
        fn ports(&self) -> &'static [u16] { self.ports }
        
        fn inspect(&self, _e: &ConntrackEntry, _p: &[u8], _d: Direction) -> Vec<Expectation> {
            Vec::new()
        }
    }

    #[test]
    fn registry_lookup_finds_registered_helper() {
        let mut r = HelperRegistry::new();
        
        let h = Arc::new(DummyHelper { name: "ftp", proto: Protocol::Tcp, ports: &[21] });
        
        r.register(h);

        assert!(r.lookup(Protocol::Tcp, 21).is_some());
        assert!(r.lookup(Protocol::Tcp, 80).is_none());
        assert!(r.lookup(Protocol::Udp, 21).is_none());
    }

    #[test]
    fn helper_can_register_on_multiple_ports() {
        let mut r = HelperRegistry::new();
        
        let h = Arc::new(DummyHelper { name: "tftp", proto: Protocol::Udp, ports: &[69, 1069] });
        
        r.register(h);

        assert_eq!(r.len(), 2);
        assert!(r.lookup(Protocol::Udp, 69).is_some());
        assert!(r.lookup(Protocol::Udp, 1069).is_some());
    }

    #[test]
    fn lookup_returns_same_arc_for_all_ports() {
        let mut r = HelperRegistry::new();
        
        let h: Arc<dyn Helper> = Arc::new(DummyHelper { name: "x", proto: Protocol::Tcp, ports: &[100, 200] });
        
        r.register(h.clone());

        let a = r.lookup(Protocol::Tcp, 100).unwrap();
        let b = r.lookup(Protocol::Tcp, 200).unwrap();
        
        assert!(Arc::ptr_eq(&a, &b));
    }
}