use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use etherparse::{Ipv4Header, NetSlice, SlicedPacket, TcpHeader, TransportSlice, UdpHeader};

use crate::data_plane::nat::bindings::BindingTable;
use crate::data_plane::nat::port_store::PortStore;
use crate::data_plane::nat::types::flow_tuple::FlowTuple;
use crate::data_plane::nat::types::flow_tuple::L4Proto;
use crate::data_plane::nat::types::nat_binding::{NatBinding, NatBindingDirection};
use crate::data_plane::nat::types::nat_outcome::NatOutcome;
use crate::data_plane::nat::types::nat_stage::NatStage;
use crate::policy::nat::nat_rule::{NatAction, NatProtocol, NatRule};
use crate::policy::nat::nat_rules::NatRules;
use crate::policy::nat::port_range::PortRange;

pub struct NatEngine {
    nat_rules: Option<Arc<NatRules>>,
    bindings: BindingTable,
    port_store: PortStore,
    interface_ips: HashMap<String, IpAddr>,
}

impl NatEngine {
    pub fn new(nat_rules: &Option<Arc<NatRules>>, interface_ips: HashMap<String, IpAddr>) -> Self {
        Self {
            nat_rules: nat_rules.clone(),
            bindings: BindingTable::new(),
            port_store: PortStore::new(PortRange::new(40000, 60000)),
            interface_ips,
        }
    }

    pub fn process_prerouting(
        &mut self,
        data: &mut [u8],
        in_interface: &str,
        in_zone: Option<&str>,
    ) -> NatOutcome {
        self.process_stage(
            data,
            NatStage::Prerouting,
            Some(in_interface),
            None,
            in_zone,
            None,
        )
    }

    pub fn process_postrouting(
        &mut self,
        data: &mut [u8],
        out_interface: &str,
        out_zone: Option<&str>,
    ) -> NatOutcome {
        self.process_stage(
            data,
            NatStage::Postrouting,
            None,
            Some(out_interface),
            None,
            out_zone,
        )
    }

    fn process_stage(
        &mut self,
        data: &mut [u8],
        stage: NatStage,
        in_interface: Option<&str>,
        out_interface: Option<&str>,
        in_zone: Option<&str>,
        out_zone: Option<&str>,
    ) -> NatOutcome {
        self.bindings.expire_old_bindings(&mut self.port_store);

        let flow_tuple = {
            let packet = match SlicedPacket::from_ethernet(data) {
                Ok(p) => p,
                Err(_) => return NatOutcome::NoMatch,
            };
            match Self::parse_flow_tuple(&packet) {
                Some(t) => t,
                None => return NatOutcome::NoMatch,
            }
        };

        if let Some((binding_id, direction)) = self.bindings.lookup(&flow_tuple) {
            let translation = self.bindings.get(binding_id).map(|b| match direction {
                NatBindingDirection::Forward => b.translated_forward.clone(),
                NatBindingDirection::Reply => b.translated_reply.clone(),
            });
            if let Some(ref t) = translation {
                Self::apply_rewrite(data, &flow_tuple, t);
            }
            return NatOutcome::AppliedExisting {
                binding_id,
                direction,
            };
        }

        let Some(rule) = self.find_matching_rule(
            stage,
            &flow_tuple,
            in_interface,
            out_interface,
            in_zone,
            out_zone,
        ) else {
            return NatOutcome::NoMatch;
        };

        let Some(binding) = self.create_binding(&rule, &flow_tuple) else {
            return NatOutcome::NoMatch;
        };

        let binding_id = binding.binding_id;
        let rule_id = binding.rule_id.clone();
        let translation = binding.translated_forward.clone();

        self.bindings.insert(binding);

        Self::apply_rewrite(data, &flow_tuple, &translation);

        NatOutcome::Created {
            binding_id,
            rule_id,
        }
    }

    fn parse_flow_tuple(packet: &SlicedPacket) -> Option<FlowTuple> {
        let (src_ip, dst_ip) = match &packet.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let h = ipv4.header();
                (
                    IpAddr::V4(h.source_addr()),
                    IpAddr::V4(h.destination_addr()),
                )
            }
            _ => return None,
        };

        let (proto, src_port, dst_port) = match &packet.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                (L4Proto::Tcp, tcp.source_port(), tcp.destination_port())
            }
            Some(TransportSlice::Udp(udp)) => {
                (L4Proto::Udp, udp.source_port(), udp.destination_port())
            }
            Some(TransportSlice::Icmpv4(_)) => (L4Proto::Icmp, 0u16, 0u16),
            _ => return None,
        };

        Some(FlowTuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        })
    }

    fn apply_rewrite(data: &mut [u8], original: &FlowTuple, translated: &FlowTuple) {
        const ETH: usize = 14;

        let Ok((mut ipv4, _)) = Ipv4Header::from_slice(&data[ETH..]) else {
            return;
        };

        let ihl = ipv4.header_len();
        let tp = ETH + ihl;

        if let (true, IpAddr::V4(v4)) = (original.src_ip != translated.src_ip, translated.src_ip) {
            ipv4.source = v4.octets();
        }

        if let (true, IpAddr::V4(v4)) = (original.dst_ip != translated.dst_ip, translated.dst_ip) {
            ipv4.destination = v4.octets();
        }

        ipv4.header_checksum = ipv4.calc_header_checksum();

        match ipv4.protocol {
            etherparse::IpNumber::TCP => {
                let Ok((mut tcp, _)) = TcpHeader::from_slice(&data[tp..]) else {
                    return;
                };
                let tcp_hdr_len = tcp.header_len();

                if original.src_port != translated.src_port {
                    tcp.source_port = translated.src_port;
                }
                if original.dst_port != translated.dst_port {
                    tcp.destination_port = translated.dst_port;
                }

                tcp.checksum = tcp
                    .calc_checksum_ipv4(&ipv4, &data[tp + tcp_hdr_len..])
                    .unwrap_or(0);

                let _ = ipv4.write(&mut std::io::Cursor::new(&mut data[ETH..]));
                let _ = tcp.write(&mut std::io::Cursor::new(&mut data[tp..]));
            }
            etherparse::IpNumber::UDP => {
                let Ok((mut udp, _)) = UdpHeader::from_slice(&data[tp..]) else {
                    return;
                };
                let udp_hdr_len = UdpHeader::LEN;

                if original.src_port != translated.src_port {
                    udp.source_port = translated.src_port;
                }
                if original.dst_port != translated.dst_port {
                    udp.destination_port = translated.dst_port;
                }

                if udp.checksum != 0 {
                    udp.checksum = udp
                        .calc_checksum_ipv4(&ipv4, &data[tp + udp_hdr_len..])
                        .unwrap_or(0);
                }

                let _ = ipv4.write(&mut std::io::Cursor::new(&mut data[ETH..]));
                let _ = udp.write(&mut std::io::Cursor::new(&mut data[tp..]));
            }
            _ => {
                let _ = ipv4.write(&mut std::io::Cursor::new(&mut data[ETH..]));
            }
        }
    }

    fn find_matching_rule(
        &self,
        stage: NatStage,
        flow: &FlowTuple,
        in_interface: Option<&str>,
        out_interface: Option<&str>,
        in_zone: Option<&str>,
        out_zone: Option<&str>,
    ) -> Option<NatRule> {
        let nat_rules = self.nat_rules.as_ref()?;

        let stage_actions: &[NatAction] = match stage {
            NatStage::Prerouting => &[NatAction::Dnat],
            NatStage::Postrouting => &[NatAction::Snat, NatAction::Pat, NatAction::Masquerade],
        };

        nat_rules
            .rules()
            .iter()
            .find(|rule| {
                if !stage_actions.contains(&rule.action()) {
                    return false;
                }

                if let Some(ri) = rule.in_interface() {
                    if in_interface != Some(ri) {
                        return false;
                    }
                }
                if let Some(ri) = rule.out_interface() {
                    if out_interface != Some(ri) {
                        return false;
                    }
                }
                if let Some(rz) = rule.in_zone() {
                    if in_zone != Some(rz) {
                        return false;
                    }
                }
                if let Some(rz) = rule.out_zone() {
                    if out_zone != Some(rz) {
                        return false;
                    }
                }

                if let Some(cidr) = rule.src_cidr() {
                    if !cidr.contains(&flow.src_ip) {
                        return false;
                    }
                }
                // For DNAT, dst_cidr is the translation target (not a match condition)
                if rule.action() != NatAction::Dnat {
                    if let Some(cidr) = rule.dst_cidr() {
                        if !cidr.contains(&flow.dst_ip) {
                            return false;
                        }
                    }
                }

                if let Some(rule_proto) = rule.protocol() {
                    let flow_proto = match flow.proto {
                        L4Proto::Tcp => NatProtocol::Tcp,
                        L4Proto::Udp => NatProtocol::Udp,
                        L4Proto::Icmp => NatProtocol::Icmp,
                    };
                    if rule_proto != flow_proto {
                        return false;
                    }
                }

                // For DNAT, src_port is the translation target port (not a match condition)
                if rule.action() != NatAction::Dnat {
                    if let Some(port) = rule.src_port() {
                        if flow.src_port != port {
                            return false;
                        }
                    }
                }
                if let Some(port) = rule.dst_port() {
                    if flow.dst_port != port {
                        return false;
                    }
                }

                true
            })
            .cloned()
    }

    fn create_binding(
        &mut self,
        rule: &NatRule,
        original_forward: &FlowTuple,
    ) -> Option<NatBinding> {
        let binding_id = self.bindings.next_binding_id();
        let now = Instant::now();

        let timeout = match original_forward.proto {
            L4Proto::Tcp => Duration::from_secs(7200),
            L4Proto::Udp => Duration::from_secs(300),
            L4Proto::Icmp => Duration::from_secs(60),
        };

        let (translated_forward, allocated_port) = match rule.action() {
            NatAction::Snat | NatAction::Pat | NatAction::Masquerade => {
                let public_ip = self.interface_ips.get(rule.out_interface()?).copied()?;

                let port = self.port_store.add(
                    public_ip,
                    original_forward.proto,
                    original_forward.src_port,
                    rule.src_port().map(|p| PortRange::new(p, p)),
                )?;

                (
                    FlowTuple {
                        src_ip: public_ip,
                        src_port: port,
                        dst_ip: original_forward.dst_ip,
                        dst_port: original_forward.dst_port,
                        proto: original_forward.proto,
                    },
                    Some(port),
                )
            }
            NatAction::Dnat => {
                let dst_ip = rule.dst_cidr()?.addr();
                // src_port is repurposed for DNAT as the target port; dst_port is the match condition
                let dst_port = rule.src_port().unwrap_or(original_forward.dst_port);

                (
                    FlowTuple {
                        src_ip: original_forward.src_ip,
                        src_port: original_forward.src_port,
                        dst_ip,
                        dst_port,
                        proto: original_forward.proto,
                    },
                    None,
                )
            }
        };

        Some(NatBinding {
            binding_id,
            rule_id: rule.id().to_string(),
            original_forward: original_forward.clone(),
            translated_forward: translated_forward.clone(),
            original_reply: translated_forward.reversed(),
            translated_reply: original_forward.reversed(),
            allocated_port,
            created_at: now,
            last_seen: now,
            expires_at: now + timeout,
        })
    }
}
