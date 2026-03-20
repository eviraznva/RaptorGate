use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use ipnet::IpNet;

use crate::data_plane::nat::nat_engine::{AddressResolver, NatEngine};
use crate::data_plane::nat::types::nat_kind_dummy::NatKindDummy;
use crate::data_plane::nat::types::nat_rule_dummy::NatRuleDummy;
use crate::data_plane::nat::types::nat_timeouts_dummy::NatTimeoutsDummy;
use crate::data_plane::nat::types::rule_match_dummy::RuleMatchDummy;

pub struct NatLabRuntime {
    pub enabled: bool,
    pub allow_all: bool,
    pub engine: Arc<Mutex<NatEngine>>,
    pub resolver: Arc<StaticAddressResolver>,
}

impl NatLabRuntime {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            allow_all: false,
            engine: Arc::new(Mutex::new(NatEngine::default())),
            resolver: Arc::new(StaticAddressResolver::default()),
        }
    }

    pub fn dummy_vagrant(allow_all: bool) -> Self {
        let resolver = Arc::new(StaticAddressResolver::with_interfaces([
            ("eth1", IpAddr::V4(Ipv4Addr::new(192, 168, 10, 254))),
            ("eth2", IpAddr::V4(Ipv4Addr::new(192, 168, 20, 254))),
        ]));

        let mut engine = NatEngine::default();
        engine.replace_rules(
            vec![NatRuleDummy {
                id: "dummy-vagrant-h1-to-h2".into(),
                priority: 10,
                match_criteria: RuleMatchDummy {
                    in_interface: Some("eth1".into()),
                    out_interface: Some("eth2".into()),
                    in_zone: Some("internal".into()),
                    out_zone: Some("dmz".into()),
                    src_cidr: Some(IpNet::V4("192.168.10.0/24".parse().expect("valid cidr"))),
                    dst_cidr: Some(IpNet::V4("192.168.20.10/32".parse().expect("valid cidr"))),
                    proto: None,
                    src_ports: None,
                    dst_ports: None,
                },
                kind: NatKindDummy::Dnat {
                    to_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 20, 10)),
                    to_port: None,
                },
                timeouts: NatTimeoutsDummy {
                    tcp_established_s: Some(3600),
                    udp_s: Some(60),
                    icmp_s: Some(30),
                },
            }],
            &["eth1".into(), "eth2".into()],
            &["internal".into(), "dmz".into()],
        );

        Self {
            enabled: true,
            allow_all,
            engine: Arc::new(Mutex::new(engine)),
            resolver,
        }
    }
}

#[derive(Default)]
pub struct StaticAddressResolver {
    interfaces: HashMap<String, IpAddr>,
}

impl StaticAddressResolver {
    pub fn with_interfaces<const N: usize>(entries: [(&str, IpAddr); N]) -> Self {
        let interfaces = entries
            .into_iter()
            .map(|(name, ip)| (name.to_string(), ip))
            .collect();
        Self { interfaces }
    }
}

impl AddressResolver for StaticAddressResolver {
    fn interface_ip(&self, interface: &str) -> Option<IpAddr> {
        self.interfaces.get(interface).copied()
    }
}
