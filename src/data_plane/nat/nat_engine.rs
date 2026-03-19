use std::net::IpAddr;
use etherparse::SlicedPacket;
use std::collections::{HashMap, HashSet};

use crate::data_plane::nat::types::nat_stage::NatStage;
use crate::data_plane::nat::types::flow_tuple::FlowTuple;
use crate::data_plane::nat::types::nat_binding::NatBinding;
use crate::data_plane::nat::types::nat_outcome::NatOutcome;
use crate::data_plane::nat::types::nat_proto_dummy::L4Proto;
use crate::data_plane::nat::types::nat_rule_dummy::NatRuleDummy;
use crate::data_plane::nat::types::port_range_dummy::PortRangeDummy;

pub trait AddressResolver {
    fn interface_ip(&self, interface: &str) -> Option<IpAddr>;
}

pub struct NatEngine {
    rules: Vec<NatRuleDummy>,
    bindings: HashMap<u64, NatBinding>,
    forward_index: HashMap<FlowTuple, u64>,
    reply_index: HashMap<FlowTuple, u64>,
    leased_ports: HashSet<(IpAddr, L4Proto, u16)>,
    next_binding_id: u64,
    default_pat_pool: PortRangeDummy,
}

impl Default for NatEngine {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            bindings: HashMap::new(),
            forward_index: HashMap::new(),
            reply_index: HashMap::new(),
            leased_ports: HashSet::new(),
            next_binding_id: 1,
            default_pat_pool: PortRangeDummy {
                start: 40000,
                end: 60000,
            },
        }
    }
}

impl NatEngine {
    pub fn replace_rules(
        &mut self,
        mut rules: Vec<NatRuleDummy>,
        known_interfaces: &[String],
        known_zones: &[String],
    ) {
        rules.sort_by_key(|r| r.priority);

        self.rules = rules;
    }

    pub fn process_stage<R: AddressResolver>(
        &mut self,
        pkt: &mut SlicedPacket<'_>,
        stage: NatStage,
        is_new_flow: bool,
        resolver: &R,
    ) -> NatOutcome {
        NatOutcome::NoMatch
    }
}