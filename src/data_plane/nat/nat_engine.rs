use std::net::IpAddr;
use etherparse::SlicedPacket;
use std::time::{Duration, Instant};
use std::collections::{HashMap, HashSet};


use crate::data_plane::nat::types::nat_stage::NatStage;
use crate::data_plane::nat::types::flow_tuple::FlowTuple;
use crate::data_plane::nat::types::nat_outcome::NatOutcome;
use crate::data_plane::nat::types::nat_binding::NatBinding;
use crate::data_plane::nat::types::nat_proto_dummy::L4Proto;
use crate::data_plane::nat::types::nat_kind_dummy::NatKindDummy;
use crate::data_plane::nat::types::nat_rule_dummy::NatRuleDummy;
use crate::data_plane::nat::types::port_range_dummy::PortRangeDummy;
use crate::data_plane::nat::types::nat_binding_direction::NatBindingDirection;

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
        _known_interfaces: &[String],
        _known_zones: &[String],
    ) {
        rules.sort_by_key(|r| r.priority);
        self.rules = rules;
    }

    pub fn process_stage<R: AddressResolver>(
        &mut self,
        pkt: &SlicedPacket<'_>,
        _stage: NatStage,
        is_new_flow: bool,
        resolver: &R,
        in_interface: Option<&str>,
        out_interface: Option<&str>,
        in_zone: Option<&str>,
        out_zone: Option<&str>,
    ) -> NatOutcome {
        self.expire_old_bindings();

        let tuple = match packet_tuple(pkt) {
            Some(tuple) => tuple,
            None => return NatOutcome::NoMatch,
        };

        if let Some(binding_id) = self.forward_index.get(&tuple).copied() {
            if let Some(binding) = self.bindings.get_mut(&binding_id) {
                binding.last_seen = Instant::now();
                return NatOutcome::AppliedExisting {
                    binding_id,
                    direction: NatBindingDirection::Forward,
                };
            }
            return NatOutcome::NoMatch;
        }

        if let Some(binding_id) = self.reply_index.get(&tuple).copied() {
            if let Some(binding) = self.bindings.get_mut(&binding_id) {
                binding.last_seen = Instant::now();
                return NatOutcome::AppliedExisting {
                    binding_id,
                    direction: NatBindingDirection::Reply,
                };
            }
            return NatOutcome::NoMatch;
        }

        if !is_new_flow {
            return NatOutcome::NoMatch;
        }

        let rule = self
            .rules
            .iter()
            .find(|rule| {
                rule.match_criteria.matches_packet(
                    pkt,
                    in_interface,
                    out_interface,
                    in_zone,
                    out_zone,
                )
            })
            .cloned();

        let Some(rule) = rule else {
            return NatOutcome::NoMatch;
        };

        let Some(binding) = self.create_binding(&rule, &tuple, resolver) else {
            return NatOutcome::NoMatch;
        };

        let binding_id = binding.binding_id;
        let rule_id = binding.rule_id.clone();
        self.install_binding(binding);

        NatOutcome::Created { binding_id, rule_id }
    }

    pub fn remove_binding(&mut self, binding_id: u64) {
        if let Some(binding) = self.bindings.remove(&binding_id) {
            self.forward_index.remove(&binding.original_forward);
            self.reply_index.remove(&binding.translated_reply);

            if let Some(port) = binding.allocated_port {
                self.leased_ports.remove(&(
                    binding.translated_forward.src_ip,
                    binding.translated_forward.proto,
                    port,
                ));
            }
        }
    }

    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    fn create_binding<R: AddressResolver>(
        &mut self,
        rule: &NatRuleDummy,
        original_forward: &FlowTuple,
        resolver: &R,
    ) -> Option<NatBinding> {
        let mut translated_forward = original_forward.clone();
        let mut allocated_port = None;

        match &rule.kind {
            NatKindDummy::Dnat { to_addr, to_port } => {
                translated_forward.dst_ip = *to_addr;
                if let Some(port) = to_port {
                    translated_forward.dst_port = *port;
                }
            }
            NatKindDummy::Snat { to_addr } => {
                translated_forward.src_ip = *to_addr;

                if translated_forward.proto.has_ports() {
                    let selected_port = self.choose_snat_port(
                        *to_addr,
                        translated_forward.proto,
                        original_forward.src_port,
                        None,
                    )?;
                    allocated_port = Some(selected_port);
                    translated_forward.src_port = selected_port;
                }
            }
            NatKindDummy::Masquerade {
                interface,
                port_pool,
            } => {
                let iface_ip = resolver.interface_ip(interface)?;
                translated_forward.src_ip = iface_ip;

                if translated_forward.proto.has_ports() {
                    let selected_port = self.choose_snat_port(
                        iface_ip,
                        translated_forward.proto,
                        original_forward.src_port,
                        *port_pool,
                    )?;
                    allocated_port = Some(selected_port);
                    translated_forward.src_port = selected_port;
                }
            }
            NatKindDummy::Pat {
                to_addr,
                interface,
                port_pool,
            } => {
                if !translated_forward.proto.has_ports() {
                    return None;
                }

                let public_ip = match (to_addr, interface.as_deref()) {
                    (Some(ip), _) => *ip,
                    (None, Some(iface)) => resolver.interface_ip(iface)?,
                    (None, None) => return None,
                };

                translated_forward.src_ip = public_ip;

                let selected_port = self.choose_snat_port(
                    public_ip,
                    translated_forward.proto,
                    original_forward.src_port,
                    Some(*port_pool),
                )?;
                allocated_port = Some(selected_port);
                translated_forward.src_port = selected_port;
            }
        }

        let original_reply = original_forward.reversed();
        let translated_reply = translated_forward.reversed();
        let now = Instant::now();
        let timeout = Self::timeout_for(rule, original_forward.proto);

        let binding = NatBinding {
            binding_id: self.next_binding_id,
            rule_id: rule.id.clone(),
            original_forward: original_forward.clone(),
            translated_forward,
            original_reply,
            translated_reply,
            allocated_port,
            created_at: now,
            last_seen: now,
            expires_at: now + timeout,
        };

        self.next_binding_id += 1;
        Some(binding)
    }

    fn install_binding(&mut self, binding: NatBinding) {
        let binding_id = binding.binding_id;
        self.forward_index
            .insert(binding.original_forward.clone(), binding_id);
        self.reply_index
            .insert(binding.translated_reply.clone(), binding_id);
        self.bindings.insert(binding_id, binding);
    }

    fn timeout_for(rule: &NatRuleDummy, proto: L4Proto) -> Duration {
        match proto {
            L4Proto::Tcp => Duration::from_secs(rule.timeouts.tcp_established_s.unwrap_or(86_400)),
            L4Proto::Udp => Duration::from_secs(rule.timeouts.udp_s.unwrap_or(60)),
            L4Proto::Icmp => Duration::from_secs(rule.timeouts.icmp_s.unwrap_or(30)),
        }
    }

    fn choose_snat_port(
        &mut self,
        public_ip: IpAddr,
        proto: L4Proto,
        original_port: u16,
        pool: Option<PortRangeDummy>,
    ) -> Option<u16> {
        if !proto.has_ports() {
            return Some(original_port);
        }

        let preferred = (public_ip, proto, original_port);
        if !self.leased_ports.contains(&preferred) {
            self.leased_ports.insert(preferred);
            return Some(original_port);
        }

        let range = pool.unwrap_or(self.default_pat_pool);
        for port in range.start..=range.end {
            let key = (public_ip, proto, port);
            if !self.leased_ports.contains(&key) {
                self.leased_ports.insert(key);
                return Some(port);
            }
        }

        None
    }

    fn expire_old_bindings(&mut self) {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .bindings
            .iter()
            .filter_map(|(id, binding)| (binding.expires_at <= now).then_some(*id))
            .collect();

        for id in expired {
            self.remove_binding(id);
        }
    }
}

fn packet_tuple(pkt: &SlicedPacket<'_>) -> Option<FlowTuple> {
    let (src_ip, dst_ip) = match pkt.net.as_ref()? {
        etherparse::NetSlice::Ipv4(ipv4) => (
            IpAddr::V4(ipv4.header().source_addr()),
            IpAddr::V4(ipv4.header().destination_addr()),
        ),
        etherparse::NetSlice::Ipv6(ipv6) => (
            IpAddr::V6(ipv6.header().source_addr()),
            IpAddr::V6(ipv6.header().destination_addr()),
        ),
        _ => return None,
    };

    let (src_port, dst_port, proto) = match pkt.transport.as_ref()? {
        etherparse::TransportSlice::Tcp(tcp) => {
            (tcp.source_port(), tcp.destination_port(), L4Proto::Tcp)
        }
        etherparse::TransportSlice::Udp(udp) => {
            (udp.source_port(), udp.destination_port(), L4Proto::Udp)
        }
        etherparse::TransportSlice::Icmpv4(_) | etherparse::TransportSlice::Icmpv6(_) => {
            (0, 0, L4Proto::Icmp)
        }
    };

    Some(FlowTuple {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
    })
}
