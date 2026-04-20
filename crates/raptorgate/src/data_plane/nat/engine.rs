use std::sync::Arc;
use std::net::IpAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::data_plane::nat::bindings::{BindingTable, PortStore};
use crate::data_plane::nat::packet::{apply_translation, parse_flow_tuple_from_ethernet, same_ip_family};

use crate::data_plane::nat::types::{
    FlowTuple, L4Proto, NatBinding, NatBindingDirection, NatOutcome, NatStage,
};

use crate::policy::nat::nat_rules::NatRules;
use crate::policy::nat::port_range::PortRange;
use crate::policy::nat::nat_rule::{NatAction, NatProtocol, NatRule};

/// Ten moduł implementuje silnik NAT odpowiedzialny za stosowanie reguł NAT, zarządzanie powiązaniami (bindings) i translację adresów/portów w pakietach sieciowych.

pub struct NatEngine {
    nat_rules: Option<Arc<NatRules>>, // Reguły NAT
    bindings: BindingTable,           // Tabela powiązań NAT
    port_store: PortStore,            // Zarządzanie pulą portów
    interface_ips: HashMap<String, Vec<IpAddr>>, // Adresy IP interfejsów
}

impl NatEngine {
    /// Tworzy nowy silnik NAT
    pub fn new(
        nat_rules: &Option<Arc<NatRules>>,
        interface_ips: HashMap<String, Vec<IpAddr>>,
    ) -> Self {
        tracing::debug!(
            nat_rule_count = nat_rules.as_ref().map_or(0, |rules| rules.rules().len()),
            interface_count = interface_ips.len(),
            "nat engine initialized"
        );

        Self {
            nat_rules: nat_rules.clone(),
            bindings: BindingTable::new(),
            port_store: PortStore::new(PortRange::new(40000, 60000)),
            interface_ips,
        }
    }

    pub fn replace_rules(&mut self, nat_rules: &Option<Arc<NatRules>>) {
        self.nat_rules = nat_rules.clone();
        self.bindings = BindingTable::new();
        self.port_store = PortStore::new(PortRange::new(40000, 60000));

        tracing::info!(
            nat_rule_count = self.nat_rules.as_ref().map_or(0, |rules| rules.rules().len()),
            "nat engine rules replaced"
        );
    }

    /// Wyszukuje oryginalny adres źródłowy na podstawie publicznego IP
    pub fn lookup_original_src(&self, public_ip: &IpAddr) -> Option<IpAddr> {
        let private_ip = self.bindings.find_private_ip_by_public(*public_ip);

        tracing::trace!(%public_ip, ?private_ip, "nat lookup original source");

        private_ip
    }

    /// Dodaje nowe powiązanie NAT
    pub fn insert_binding(&mut self, binding: NatBinding) {
        tracing::debug!(
            binding_id = binding.binding_id,
            rule_id = %binding.rule_id,
            original = ?binding.original_forward,
            translated = ?binding.translated_forward,
            "nat insert binding"
        );

        self.bindings.insert(binding);
    }

    pub fn nat_rules(&self) -> Option<Arc<NatRules>> {
        self.nat_rules.clone()
    }

    /// Zwraca kolejny dostępny identyfikator powiązania
    pub fn next_binding_id(&mut self) -> u64 {
        let binding_id = self.bindings.next_binding_id();

        tracing::trace!(binding_id, "nat next binding id");

        binding_id
    }

    /// Przetwarza pakiet na etapie PREROUTING (np. DNAT)
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

    /// Przetwarza pakiet na etapie POSTROUTING (np. SNAT, MASQUERADE)
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

    /// Główna logika przetwarzania pakietu na danym etapie NAT
    fn process_stage(
        &mut self,
        data: &mut [u8],
        stage: NatStage,
        in_interface: Option<&str>,
        out_interface: Option<&str>,
        in_zone: Option<&str>,
        out_zone: Option<&str>,
    ) -> NatOutcome {
        tracing::trace!(
            ?stage,
            in_interface,
            out_interface,
            in_zone,
            out_zone,
            packet_len = data.len(),
            "nat processing stage"
        );
        self.bindings.expire_old_bindings(&mut self.port_store);

        let flow = match parse_flow_tuple_from_ethernet(data) {
            Some(flow) => flow,
            None => {
                tracing::trace!(?stage, "nat skipping packet: unable to parse flow tuple");
                return NatOutcome::NoMatch;
            }
        };

        if !can_translate_flow(&flow) {
            tracing::trace!(?stage, ?flow, "nat skipping unsupported flow");
            return NatOutcome::NoMatch;
        }

        tracing::trace!(?stage, ?flow, "nat parsed flow");

        // Sprawdzenie, czy istnieje już powiązanie dla tego flow
        if let Some((binding_id, direction)) = self.bindings.lookup(&flow) {
            let translation = self.bindings.get(binding_id).map(|binding| match direction {
                NatBindingDirection::Forward => binding.translated_forward.clone(),
                NatBindingDirection::Reply => binding.translated_reply.clone(),
            });

            if let Some(translation) = translation {
                if apply_translation(data, &flow, &translation) {
                    tracing::debug!(
                        ?stage,
                        ?flow,
                        binding_id,
                        ?direction,
                        translated = ?translation,
                        "nat applied existing binding"
                    );

                    return NatOutcome::AppliedExisting {
                        binding_id,
                        direction,
                    };
                }
            }

            tracing::warn!(
                ?stage,
                ?flow,
                binding_id,
                ?direction,
                "nat binding matched but packet rewrite failed"
            );

            return NatOutcome::NoMatch;
        }

        // Szukanie pasującej reguły NAT
        let Some(rule) = self.find_matching_rule(
            stage,
            &flow,
            in_interface,
            out_interface,
            in_zone,
            out_zone,
        ) else {
            tracing::trace!(?stage, ?flow, "nat no matching rule");
            return NatOutcome::NoMatch;
        };

        tracing::debug!(
            ?stage,
            ?flow,
            rule_id = %rule.id(),
            action = ?rule.action(),
            "nat matched rule"
        );

        // Tworzenie nowego powiązania NAT
        let Some(binding) = self.create_binding(&rule, &flow) else {
            tracing::debug!(
                ?stage,
                ?flow,
                rule_id = %rule.id(),
                "nat failed to create binding"
            );

            return NatOutcome::NoMatch;
        };

        let binding_id = binding.binding_id;

        let rule_id = binding.rule_id.clone();

        let translated = binding.translated_forward.clone();

        if !apply_translation(data, &flow, &translated) {
            tracing::warn!(
                ?stage,
                ?flow,
                binding_id,
                rule_id = %rule_id,
                translated = ?translated,
                "nat created binding but packet rewrite failed"
            );

            return NatOutcome::NoMatch;
        }

        tracing::debug!(
            ?stage,
            ?flow,
            binding_id,
            rule_id = %rule_id,
            translated = ?translated,
            "nat created new binding"
        );
        
        self.bindings.insert(binding);
        NatOutcome::Created {
            binding_id,
            rule_id,
        }
    }

    /// Wyszukuje regułę NAT pasującą do danego flow i etapu
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
            NatStage::Prerouting => &[NatAction::Dnat, NatAction::Pat],
            NatStage::Postrouting => &[NatAction::Snat, NatAction::Masquerade],
        };

        let matched = nat_rules.rules().iter()
            .find(|rule| {
                if !stage_actions.contains(&rule.action()) {
                    return false;
                }

                if let Some(rule_in) = rule.in_interface() {
                    if in_interface != Some(rule_in) {
                        return false;
                    }
                }

                if let Some(rule_out) = rule.out_interface() {
                    if out_interface != Some(rule_out) {
                        return false;
                    }
                }

                if let Some(rule_zone) = rule.in_zone() {
                    if in_zone != Some(rule_zone) {
                        return false;
                    }
                }

                if let Some(rule_zone) = rule.out_zone() {
                    if out_zone != Some(rule_zone) {
                        return false;
                    }
                }

                if let Some(cidr) = rule.src_cidr() {
                    if !cidr.contains(&flow.src_ip) {
                        return false;
                    }
                }
                if let Some(cidr) = rule.dst_cidr() {
                    if !cidr.contains(&flow.dst_ip) {
                        return false;
                    }
                }

                if let Some(rule_proto) = rule.protocol() {
                    if flow_nat_protocol(flow.proto) != rule_proto {
                        return false;
                    }
                }

                if let Some(src_port) = rule.src_port() {
                    if flow.src_port != src_port {
                        return false;
                    }
                }

                if let Some(dst_port) = rule.dst_port() {
                    if flow.dst_port != dst_port {
                        return false;
                    }
                }

                true
            }).cloned();

        if let Some(rule) = matched.as_ref() {
            tracing::trace!(
                ?stage,
                ?flow,
                rule_id = %rule.id(),
                action = ?rule.action(),
                "nat rule selected"
            );
        }

        matched
    }

    /// Tworzy nowe powiązanie NAT na podstawie reguły i flow
    fn create_binding(&mut self, rule: &NatRule, original_forward: &FlowTuple) -> Option<NatBinding> {
        tracing::trace!(
            rule_id = %rule.id(),
            action = ?rule.action(),
            original = ?original_forward,
            "nat creating binding"
        );

        let timeout = binding_timeout_for(original_forward.proto);

        let binding_id = self.bindings.next_binding_id();

        let (translated_forward, allocated_port) = match rule.action() {
            NatAction::Snat => {
                let translated_ip = rule.translated_ip()?;

                if !same_ip_family(translated_ip, original_forward.src_ip) {
                    tracing::debug!(
                        rule_id = %rule.id(),
                        original_src = %original_forward.src_ip,
                        translated_src = %translated_ip,
                        "nat rejected snat binding due to mixed address families"
                    );

                    return None;
                }

                (
                    FlowTuple {
                        src_ip: translated_ip,
                        src_port: original_forward.src_port,
                        dst_ip: original_forward.dst_ip,
                        dst_port: original_forward.dst_port,
                        proto: original_forward.proto,
                    },
                    None,
                )
            }
            NatAction::Masquerade => {
                let public_ip = self.interface_ip_for(
                    rule.out_interface()?,
                    original_forward.src_ip,
                )?;

                let port = self.port_store.add(
                    public_ip,
                    original_forward.proto,
                    original_forward.src_port,
                    rule.translated_port().map(|port| PortRange::new(port, port)),
                )?;

                (
                    FlowTuple {
                        src_ip: public_ip,
                        src_port: port,
                        dst_ip: original_forward.dst_ip,
                        dst_port: original_forward.dst_port,
                        proto: original_forward.proto,
                    },
                    original_forward.proto.has_ports().then_some(port),
                )
            }
            NatAction::Dnat => {
                let dst_ip = rule.translated_ip()?;

                if !same_ip_family(dst_ip, original_forward.dst_ip) {
                    tracing::debug!(
                        rule_id = %rule.id(),
                        original_dst = %original_forward.dst_ip,
                        translated_dst = %dst_ip,
                        "nat rejected dnat binding due to mixed address families"
                    );

                    return None;
                }

                (
                    FlowTuple {
                        src_ip: original_forward.src_ip,
                        src_port: original_forward.src_port,
                        dst_ip,
                        dst_port: rule.translated_port().unwrap_or(original_forward.dst_port),
                        proto: original_forward.proto,
                    },
                    None,
                )
            }
            NatAction::Pat => {
                let dst_ip = rule.translated_ip()?;
                let dst_port = rule.translated_port()?;

                if !same_ip_family(dst_ip, original_forward.dst_ip) {
                    tracing::debug!(
                        rule_id = %rule.id(),
                        original_dst = %original_forward.dst_ip,
                        translated_dst = %dst_ip,
                        "nat rejected pat binding due to mixed address families"
                    );

                    return None;
                }

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

        let binding = build_binding(
            binding_id,
            rule.id().to_string(),
            original_forward.clone(),
            translated_forward,
            allocated_port,
            timeout,
        );

        tracing::trace!(
            binding_id = binding.binding_id,
            rule_id = %binding.rule_id,
            original = ?binding.original_forward,
            translated = ?binding.translated_forward,
            allocated_port = binding.allocated_port,
            "nat binding created"
        );

        Some(binding)
    }

    /// Zwraca adres IP interfejsu o tej samej rodzinie co podany adres
    fn interface_ip_for(&self, interface: &str, same_family_as: IpAddr) -> Option<IpAddr> {
        let selected = self.interface_ips.get(interface)?.iter().copied()
            .find(|candidate| same_ip_family(*candidate, same_family_as));

        tracing::trace!(
            interface,
            same_family_as = %same_family_as,
            ?selected,
            "nat resolved interface address"
        );

        selected
    }
}

/// Buduje strukturę powiązania NAT
pub(crate) fn build_binding(
    binding_id: u64,
    rule_id: String,
    original_forward: FlowTuple,
    translated_forward: FlowTuple,
    allocated_port: Option<u16>,
    timeout: Duration,
) -> NatBinding {
    let now = Instant::now();

    let binding = NatBinding {
        binding_id,
        rule_id,
        original_reply: translated_forward.reversed(),
        translated_reply: original_forward.reversed(),
        original_forward,
        translated_forward,
        allocated_port,
        created_at: now,
        last_seen: now,
        expires_at: now + timeout,
    };

    tracing::trace!(
        binding_id = binding.binding_id,
        rule_id = %binding.rule_id,
        original = ?binding.original_forward,
        translated = ?binding.translated_forward,
        timeout_secs = timeout.as_secs(),
        "nat built binding"
    );

    binding
}

/// Zwraca timeout powiązania w zależności od protokołu
pub(crate) fn binding_timeout_for(proto: L4Proto) -> Duration {
    match proto {
        L4Proto::Tcp => Duration::from_secs(7200),
        L4Proto::Udp => Duration::from_secs(300),
        L4Proto::Icmp => Duration::from_secs(60),
    }
}

/// Mapuje L4Proto na NatProtocol
fn flow_nat_protocol(proto: L4Proto) -> NatProtocol {
    match proto {
        L4Proto::Tcp => NatProtocol::Tcp,
        L4Proto::Udp => NatProtocol::Udp,
        L4Proto::Icmp => NatProtocol::Icmp,
    }
}

/// Sprawdza, czy dany flow może być translantowany (np. nie translantujemy ICMPv6)
fn can_translate_flow(flow: &FlowTuple) -> bool {
    !(flow.proto == L4Proto::Icmp && matches!(flow.src_ip, IpAddr::V6(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn flow(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> FlowTuple {
        FlowTuple {
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
            src_port,
            dst_port,
            proto: L4Proto::Tcp,
        }
    }

    #[test]
    fn pat_binding_rewrites_destination_ip_and_port() {
        let mut engine = NatEngine::new(&None, HashMap::new());
        let rule = NatRule::new(
            "pat-1".into(),
            10,
            None,
            None,
            None,
            None,
            None,
            Some("192.0.2.10/32".parse().unwrap()),
            Some(NatProtocol::Tcp),
            None,
            Some(443),
            Some("10.0.0.10".parse().unwrap()),
            Some(8443),
            NatAction::Pat,
        );

        let binding = engine
            .create_binding(&rule, &flow([198, 51, 100, 25], 50000, [192, 0, 2, 10], 443))
            .unwrap();

        assert_eq!(
            binding.translated_forward.dst_ip,
            "10.0.0.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(binding.translated_forward.dst_port, 8443);
    }

    #[test]
    fn snat_binding_rewrites_source_ip_without_port_translation() {
        let mut engine = NatEngine::new(&None, HashMap::new());
        let rule = NatRule::new(
            "snat-1".into(),
            10,
            None,
            None,
            None,
            None,
            Some("10.0.0.10/32".parse().unwrap()),
            None,
            None,
            None,
            None,
            Some("198.51.100.10".parse().unwrap()),
            None,
            NatAction::Snat,
        );

        let binding = engine
            .create_binding(&rule, &flow([10, 0, 0, 10], 51000, [203, 0, 113, 20], 443))
            .unwrap();

        assert_eq!(
            binding.translated_forward.src_ip,
            "198.51.100.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(binding.translated_forward.src_port, 51000);
        assert!(binding.allocated_port.is_none());
    }
}
