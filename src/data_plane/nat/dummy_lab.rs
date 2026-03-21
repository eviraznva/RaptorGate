use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use crate::data_plane::nat::nat_engine::{AddressResolver, NatEngine};

pub struct NatLabRuntime {
    pub enabled: bool,
    pub allow_all: bool,
    pub engine: Mutex<NatEngine>,
    pub resolver: StaticAddressResolver,
}

impl NatLabRuntime {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            allow_all: false,
            engine: Mutex::new(NatEngine::default()),
            resolver: StaticAddressResolver::default(),
        }
    }

    pub fn dummy_vagrant(allow_all: bool) -> Self {
        Self {
            enabled: true,
            allow_all,
            engine: Mutex::new(NatEngine::default()),
            resolver: StaticAddressResolver::vagrant_defaults(),
        }
    }
}

#[derive(Default)]
pub struct StaticAddressResolver {
    interfaces: HashMap<String, IpAddr>,
}

impl StaticAddressResolver {
    fn vagrant_defaults() -> Self {
        let mut interfaces = HashMap::new();
        interfaces.insert("eth1".to_string(), IpAddr::V4(Ipv4Addr::new(192, 168, 10, 10)));
        interfaces.insert("eth2".to_string(), IpAddr::V4(Ipv4Addr::new(192, 168, 20, 10)));
        Self { interfaces }
    }
}

impl AddressResolver for StaticAddressResolver {
    fn interface_ip(&self, interface: &str) -> Option<IpAddr> {
        self.interfaces.get(interface).copied()
    }
}
