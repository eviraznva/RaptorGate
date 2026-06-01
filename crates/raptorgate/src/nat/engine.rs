use std::net::IpAddr;
use std::sync::{Arc, OnceLock, Weak};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use anyhow::{Result, bail};

use crate::nat::range::NatRange;
use crate::nat::port_alloc::PortStore;
use crate::nat::manip::{ManipMask, ManipType};
use crate::conntrack::tuple::{FlowTuple, Protocol};
use crate::conntrack::table::{Conntrack, LookupResult};
use crate::conntrack::observer::{CtObserver, DestroyReason};
use crate::nat::config::{NatAction, NatProtocol, NatRule, NatRules};
use crate::conntrack::entry::{ConntrackEntry, CtInfo, CtStatus, NatTransform, TupleManip};

pub struct NatEngine {
    rules: ArcSwap<Option<Arc<NatRules>>>,
    port_store: Arc<PortStore>,
    interface_ips: ArcSwap<HashMap<String, Vec<IpAddr>>>,
    conntrack: OnceLock<Weak<Conntrack>>,
    binding_id_seq: AtomicU64,
    seed_key: u64,
}

#[derive(Debug, Clone)]
pub enum NatOutcome {
    /// Pakiet nie pasuje do żadnej reguły / nie wymaga NAT.
    NoMatch,
    /// `entry.nat` był już ustawiony — apply'd existing transform.
    AppliedExisting { binding_id: u64 },
    /// Nowo utworzony transform (first packet flow).
    Created { binding_id: u64, rule_id: String },
}

impl NatEngine {
    pub fn new(rules: Option<Arc<NatRules>>, interface_ips: HashMap<String, Vec<IpAddr>>) -> Arc<Self> {
        Arc::new(Self {
            rules: ArcSwap::from_pointee(rules),
            port_store: Arc::new(PortStore::new()),
            interface_ips: ArcSwap::from_pointee(interface_ips),
            conntrack: OnceLock::new(),
            binding_id_seq: AtomicU64::new(1),
            seed_key: rand::random(),
        })
    }

    /// PREROUTING: DNAT i PAT
    pub fn prerouting(&self, packet: &mut [u8], ct: &Arc<ConntrackEntry>, _info: CtInfo, in_interface: &str, in_zone: Option<&str>) -> NatOutcome {
        self.process_stage(packet, ct, ManipType::Destination, Some(in_interface), None, in_zone, None)
    }

    /// POSTROUTING: SNAT i MASQUERADE
    pub fn postrouting(&self, packet: &mut [u8], ct: &Arc<ConntrackEntry>, _info: CtInfo, out_interface: &str, out_zone: Option<&str>) -> NatOutcome {
        self.process_stage(packet, ct, ManipType::Source, None, Some(out_interface), None, out_zone)
    }

    fn process_stage(&self,
        packet: &mut [u8],
        ct: &Arc<ConntrackEntry>,
        manip: ManipType,
        in_interface: Option<&str>,
        out_interface: Option<&str>,
        in_zone: Option<&str>,
        out_zone: Option<&str>) -> NatOutcome {

        if let Some(existing) = ct.nat.lock().clone() {
            if !self.would_apply_in_stage(packet, ct, &existing, manip) {
                return NatOutcome::NoMatch;
            }
            return self.apply_existing(packet, ct, &existing, manip);
        }

        let Some(rule) = self.find_matching_rule(ct, manip, in_interface, out_interface, in_zone, out_zone) else {
            return NatOutcome::NoMatch;
        };

        let Some(range) = self.range_from_action(rule.action(), out_interface, ct) else {
            return NatOutcome::NoMatch;
        };

        let transform = match self.setup_nat(ct, manip, range, rule.id()) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(ct_id = ct.id, rule_id = rule.id(), error = %e, "setup_nat failed");
                return NatOutcome::NoMatch;
            }
        };

        if !self.apply_to_packet(packet, ct, &transform, manip) {
            return NatOutcome::NoMatch;
        }

        ct.set_status(match manip {
            ManipType::Source      => CtStatus::SRC_NAT_DONE,
            ManipType::Destination => CtStatus::DST_NAT_DONE,
        });

        NatOutcome::Created { binding_id: transform.binding_id, rule_id: rule.id().to_string() }
    }

    pub fn attach_conntrack(&self, ct: &Arc<Conntrack>) {
        let _ = self.conntrack.set(Arc::downgrade(ct));
    }

    pub fn replace_rules(&self, rules: Option<Arc<NatRules>>) {
        self.rules.store(Arc::new(rules));
    }

    pub fn rules(&self) -> Option<Arc<NatRules>> {
        self.rules.load().as_ref().clone()
    }

    pub fn port_store(&self) -> &Arc<PortStore> { &self.port_store }

    /// Snapshot of the interface → IPs map, used to derive kernel coexistence
    /// rules (e.g. resolving the MASQUERADE source IP for an out-interface).
    pub fn interface_ips_snapshot(&self) -> Arc<HashMap<String, Vec<IpAddr>>> {
        self.interface_ips.load_full()
    }

    fn would_apply_in_stage(&self, packet: &[u8], ct: &Arc<ConntrackEntry>, t: &NatTransform, manip: ManipType) -> bool {
        match (self.detect_direction(ct, packet, Some(t)), manip) {
            (PacketDirection::Original, ManipType::Source) => t.has_src_manip(),
            (PacketDirection::Original, ManipType::Destination) => t.has_dst_manip(),
            (PacketDirection::Reply, ManipType::Source) => t.has_dst_manip(),
            (PacketDirection::Reply, ManipType::Destination) => t.has_src_manip(),
        }
    }

    fn apply_existing(&self, packet: &mut [u8], ct: &Arc<ConntrackEntry>, transform: &NatTransform, manip: ManipType) -> NatOutcome {
        if !self.apply_to_packet(packet, ct, transform, manip) {
            return NatOutcome::NoMatch;
        }

        ct.set_status(match manip {
            ManipType::Source      => CtStatus::SRC_NAT_DONE,
            ManipType::Destination => CtStatus::DST_NAT_DONE,
        });

        NatOutcome::AppliedExisting { binding_id: transform.binding_id }
    }

    fn apply_to_packet(&self, packet: &mut [u8], ct: &Arc<ConntrackEntry>, transform: &NatTransform, _manip: ManipType) -> bool {
        let direction = self.detect_direction(ct, packet, Some(transform));

        let (orig_for_apply, translated) = match direction {
            PacketDirection::Original => {
                let translated = apply_transform_to_tuple_original(&ct.original, transform);
                (ct.original, translated)
            }
            PacketDirection::Reply => {
                let reply = ct.reply.lock().clone();
                (reply, ct.original.invert())
            }
        };

        crate::nat::packet::apply_translation(packet, &orig_for_apply, &translated)
    }

    /// Direction wykrywany przez parsing pakietu i porównanie z `ct.original`.
    /// Pipeline (ConntrackInStage) ma już tę informację w `PacketContext` ale
    /// engine tu jej nie dostaje — recompute z bytes.
    fn detect_direction(&self, ct: &Arc<ConntrackEntry>, packet: &[u8], transform: Option<&NatTransform>) -> PacketDirection {
        match crate::nat::packet::parse_flow_tuple_from_ethernet(packet) {
            Some(flow) if tuple_matches_direction(&flow, &ct.original) => {
                PacketDirection::Original
            }
            Some(flow) if transform
                .map(|t| tuple_matches_direction(&flow, &apply_transform_to_tuple_original(&ct.original, t)))
                .unwrap_or(false) => PacketDirection::Original,
            Some(_) => PacketDirection::Reply,
            None => PacketDirection::Original,
        }
    }

    fn find_matching_rule(&self,
        ct: &Arc<ConntrackEntry>,
        manip: ManipType,
        in_interface: Option<&str>,
        out_interface: Option<&str>,
        in_zone: Option<&str>,
        out_zone: Option<&str>) -> Option<Arc<NatRule>> {

        let rules = self.rules.load();
        let rules = rules.as_ref().as_ref()?;

        let allowed = |action: &NatAction| -> bool {
            match (manip, action) {
                (ManipType::Destination, NatAction::Dnat { .. }) => true,
                (ManipType::Destination, NatAction::Pat  { .. }) => true,
                (ManipType::Source, NatAction::Snat       { .. }) => true,
                (ManipType::Source, NatAction::Masquerade { .. }) => true,
                _ => false,
            }
        };

        for rule in rules.rules() {
            if !allowed(rule.action()) { continue; }

            if let Some(req) = rule.in_interface()  { if in_interface  != Some(req) { continue; } }
            if let Some(req) = rule.out_interface() { if out_interface != Some(req) { continue; } }
            if let Some(req) = rule.in_zone()       { if in_zone       != Some(req) { continue; } }
            if let Some(req) = rule.out_zone()      { if out_zone      != Some(req) { continue; } }

            if !proto_matches(rule.protocol(), ct.original.protocol) { continue; }

            if !port_in_range(rule.match_src_port_range(), ct.original.src_port) { continue; }
            if !port_in_range(rule.match_dst_port_range(), ct.original.dst_port) { continue; }

            if !flow_matches_action(rule.action(), &ct.original) { continue; }

            return Some(Arc::new(rule.clone()));
        }

        None
    }

    fn range_from_action(&self, action: &NatAction, out_interface: Option<&str>, ct: &Arc<ConntrackEntry>) -> Option<NatRange> {
        match action {
            NatAction::Snat { translated_ip, src_port_range, .. } => {
                Some(match src_port_range {
                    Some((lo, hi)) => NatRange::single_ip_port_range(*translated_ip, *lo, *hi),
                    None           => NatRange::single_ip_default(*translated_ip),
                })
            },

            NatAction::Dnat { translated_ip, translated_port, .. } => {
                let port = translated_port.unwrap_or(ct.original.dst_port);
                Some(NatRange::single_ip_port(*translated_ip, port))
            },

            NatAction::Pat { translated_ip, translated_port, .. } => {
                Some(NatRange::single_ip_port(*translated_ip, *translated_port))
            },

            NatAction::Masquerade { src_port_range, .. } => {
                let iface = out_interface?;
                let ips = self.interface_ips.load();
                let ip = ips.get(iface)?.iter().find(|ip| ip.is_ipv4()).copied()?;

                Some(match src_port_range {
                    Some((lo, hi)) => NatRange::single_ip_port_range(ip, *lo, *hi),
                    None           => NatRange::single_ip_default(ip),
                })
            },
        }
    }

    pub fn replace_interface_ips(&self, new_ips: HashMap<String, Vec<IpAddr>>) {
        let old_snapshot = self.interface_ips.load_full();

        let old_ips: HashSet<IpAddr> = old_snapshot.values().flatten().copied().collect();
        let new_ips_set: HashSet<IpAddr> = new_ips.values().flatten().copied().collect();
        let removed: HashSet<IpAddr> = old_ips.difference(&new_ips_set).copied().collect();

        self.interface_ips.store(Arc::new(new_ips));

        if removed.is_empty() { return; }

        let Some(conntrack) = self.conntrack() else {
            tracing::warn!("interface ips changed but conntrack not attached, skipping flush");
            return;
        };

        let mut flushed = 0u32;

        for ct in conntrack.iter_entries() {
            let Some(allocated) = ct.nat.lock().as_ref().and_then(|t| t.allocated_ip) else { continue };

            if removed.contains(&allocated) {
                conntrack.destroy(&ct, DestroyReason::Manual);
                flushed += 1;
            }
        }

        if flushed > 0 {
            tracing::info!(removed_ips = removed.len(), flushed_entries = flushed, "masquerade flush after ip change");
        }
    }

    fn conntrack(&self) -> Option<Arc<Conntrack>> {
        self.conntrack.get().and_then(Weak::upgrade)
    }

    fn setup_nat(&self, ct: &Arc<ConntrackEntry>, manip: ManipType, range: NatRange, rule_id: &str) -> Result<NatTransform> {
        let proto = ct.original.protocol;

        let mut guard = ct.nat.lock();

        if let Some(existing) = guard.as_ref() {
            tracing::trace!(ct_id = ct.id, "setup_nat idempotent: returning existing transform");
            return Ok(existing.clone());
        }

        let mask = ManipMask::from_type(manip);
        let seed = self.compute_seed(&ct.original);

        let candidate = self.allocate_unique_tuple(ct, manip, &range, proto, seed)?;

        let manip_tuple = TupleManip { ip: candidate.ip, port: candidate.port };

        let transform = NatTransform {
            rule_id: rule_id.to_string(),
            binding_id: ct.id,
            manip_bits: mask.bits(),
            src_manip: if mask.contains_src() { Some(manip_tuple.clone()) } else { None },
            dst_manip: if mask.contains_dst() { Some(manip_tuple.clone()) } else { None },
            allocated_ip: candidate.alloc_ip,
            allocated_port: candidate.alloc_port,
            proto,
        };

        *guard = Some(transform.clone());

        ct.set_status(match manip {
            ManipType::Source      => CtStatus::SRC_NAT,
            ManipType::Destination => CtStatus::DST_NAT,
        });

        let reply = ct.original.invert();
        let new_reply = apply_transform_to_tuple(&reply, &transform);

        ct.set_reply_tuple(new_reply);

        tracing::debug!(
              ct_id = ct.id,
              rule_id,
              ?manip,
              allocated_ip = ?candidate.alloc_ip,
              allocated_port = ?candidate.alloc_port,
              "setup_nat installed transform"
          );

        Ok(transform)
    }

    fn allocate_unique_tuple(&self, ct: &Arc<ConntrackEntry>, manip: ManipType, range: &NatRange, proto: Protocol, seed: u64) -> Result<Candidate> {
        // Destination NAT (DNAT/PAT) with a fixed port: multiple connections share the
        // same translated port — uniqueness comes from the client's source tuple, not
        // from port allocation.  Skip PortStore to avoid "port exhausted" on the second
        // concurrent connection.
        if manip == ManipType::Destination && range.port_specified() && range.min_port == range.max_port {
            let candidate = Candidate {
                ip: range.min_ip,
                port: Some(range.min_port),
                alloc_ip: None,
                alloc_port: None,
            };

            if self.reply_collides(ct, manip, &candidate) {
                bail!("destination NAT reply collision for {:?}", range);
            }

            return Ok(candidate);
        }

        const MAX_ATTEMPTS: u32 = 16;

        let original_port = match manip {
            ManipType::Source      => ct.original.src_port,
            ManipType::Destination => ct.original.dst_port,
        };

        for attempt in 0..MAX_ATTEMPTS {
            let alloc_port = self.port_store.alloc(range, proto, original_port, seed.wrapping_add(attempt as u64));

            let port = match (range.port_specified(), alloc_port) {
                (true, Some(p)) => Some(p),
                (true, None) => bail!("port allocator exhausted in range {:?}", range),
                (false, _) => None,
            };

            let candidate = Candidate {
                ip: range.min_ip,
                port,
                alloc_ip: port.map(|_| range.min_ip),
                alloc_port: port,
            };

            if !self.reply_collides(ct, manip, &candidate) {
                return Ok(candidate);
            }

            if let (Some(ip), Some(p)) = (candidate.alloc_ip, candidate.alloc_port) {
                self.port_store.release(ip, proto, p);
            }

            tracing::trace!(ct_id = ct.id, attempt, "setup_nat reply collision, retrying");
        }

        bail!("setup_nat: cannot find unique tuple after {MAX_ATTEMPTS} attempts");
    }

    fn reply_collides(&self, ct: &Arc<ConntrackEntry>, manip: ManipType, c: &Candidate) -> bool {
        let Some(conntrack) = self.conntrack() else { return false; };

        let reply = ct.original.invert();

        let probe = match manip {
            ManipType::Source => FlowTuple {
                dst_ip: c.ip,
                dst_port: c.port.unwrap_or(reply.dst_port),
                ..reply
            },

            ManipType::Destination => FlowTuple {
                src_ip: c.ip,
                src_port: c.port.unwrap_or(reply.src_port),
                ..reply
            },
        };

        matches!(conntrack.lookup(&probe), LookupResult::Found { .. })
    }

    fn compute_seed(&self, tuple: &FlowTuple) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut h = std::collections::hash_map::DefaultHasher::new();

        tuple.src_ip.hash(&mut h);
        tuple.dst_ip.hash(&mut h);
        self.seed_key.hash(&mut h);

        h.finish()
    }

    pub(crate) fn next_binding_id(&self) -> u64 {
        self.binding_id_seq.fetch_add(1, Ordering::Relaxed)
    }
}

impl CtObserver for NatEngine {
    fn on_destroy(&self, entry: &ConntrackEntry, _reason: DestroyReason) {
        let Some(transform) = entry.nat.lock().clone() else { return };

        if let (Some(ip), Some(port)) = (transform.allocated_ip, transform.allocated_port) {
            self.port_store.release(ip, transform.proto, port);
            tracing::trace!(ct_id = entry.id, %ip, port, "released port on destroy");
        }
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    ip: IpAddr,
    port: Option<u16>,
    alloc_ip: Option<IpAddr>,
    alloc_port: Option<u16>,
}

fn apply_transform_to_tuple(reply: &FlowTuple, t: &NatTransform) -> FlowTuple {
    let mut out = *reply;

    if t.has_src_manip() {
        if let Some(m) = &t.src_manip {
            out.dst_ip = m.ip;
            if let Some(p) = m.port { out.dst_port = p; }
        }
    }

    if t.has_dst_manip() {
        if let Some(m) = &t.dst_manip {
            out.src_ip = m.ip;
            if let Some(p) = m.port { out.src_port = p; }
        }
    }

    out
}

fn apply_transform_to_tuple_original(original: &FlowTuple, t: &NatTransform) -> FlowTuple {
    let mut out = *original;

    if let Some(m) = &t.src_manip {
        out.src_ip = m.ip;
        if let Some(p) = m.port { out.src_port = p; }
    }

    if let Some(m) = &t.dst_manip {
        out.dst_ip = m.ip;
        if let Some(p) = m.port { out.dst_port = p; }
    }

    out
}

#[derive(Debug, Clone, Copy)]
enum PacketDirection { Original, Reply }

fn tuple_matches_direction(packet: &FlowTuple, tuple: &FlowTuple) -> bool {
    packet.src_ip == tuple.src_ip
        && packet.dst_ip == tuple.dst_ip
        && packet.src_port == tuple.src_port
        && packet.dst_port == tuple.dst_port
        && packet.protocol == tuple.protocol
}

/// Match port flow vs Optional zakres reguły. None = brak ograniczenia (zawsze pasuje).
fn port_in_range(range: Option<(u16, u16)>, port: u16) -> bool {
    match range {
        None => true,
        Some((lo, hi)) => port >= lo && port <= hi,
    }
}

fn proto_matches(rule_proto: NatProtocol, flow_proto: Protocol) -> bool {
    match (rule_proto, flow_proto) {
        (NatProtocol::All, _)              => true,
        (NatProtocol::Tcp, Protocol::Tcp)  => true,
        (NatProtocol::Udp, Protocol::Udp)  => true,
        (NatProtocol::Icmp, Protocol::Icmp) => true,
        (NatProtocol::Icmp, Protocol::IcmpV6) => true,
        _ => false,
    }
}

fn flow_matches_action(action: &NatAction, flow: &FlowTuple) -> bool {
    match action {
        NatAction::Snat { src_cidr, .. } => src_cidr.contains(&flow.src_ip),
        NatAction::Dnat { dst_cidr, .. } => dst_cidr.contains(&flow.dst_ip),
        NatAction::Pat  { dst_ip, dst_port, .. } => flow.dst_ip == *dst_ip && flow.dst_port == *dst_port,
        NatAction::Masquerade { src_cidr, .. } => {
            src_cidr.map(|c| c.contains(&flow.src_ip)).unwrap_or(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::net::Ipv4Addr;
    use std::collections::HashMap;
    use std::time::Duration;
    use crate::nat::config::{NatAction, NatRule, NatRules, NatProtocol};
    use crate::conntrack::table::Conntrack;
    use crate::conntrack::config::ConntrackConfig;
    use crate::conntrack::proto::{ProtoRegistry, ProtoState};
    use crate::conntrack::proto::tcp::TcpProtoState;
    use crate::conntrack::tuple::{FlowTuple, Protocol};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn dnat_rule(id: &str, dst_cidr: &str, translated_ip: &str, translated_port: Option<u16>) -> NatRule {
        NatRule::new(
            id.into(), 1,
            None, None, None, None,
            NatProtocol::All, None, None,
            NatAction::Dnat {
                dst_cidr: dst_cidr.parse().unwrap(),
                translated_ip: translated_ip.parse().unwrap(),
                translated_port,
            },
        )
    }

    fn snat_rule(id: &str, src_cidr: &str, translated_ip: &str) -> NatRule {
        NatRule::new(
            id.into(), 1,
            None, None, None, None,
            NatProtocol::All, None, None,
            NatAction::Snat {
                src_cidr: src_cidr.parse().unwrap(),
                translated_ip: translated_ip.parse().unwrap(),
                src_port_range: None,
            },
        )
    }

    fn pat_rule(id: &str, dst_ip: &str, dst_port: u16, translated_ip: &str, translated_port: u16) -> NatRule {
        NatRule::new(
            id.into(), 1,
            None, None, None, None,
            NatProtocol::All, None, None,
            NatAction::Pat {
                dst_ip: dst_ip.parse().unwrap(),
                dst_port,
                translated_ip: translated_ip.parse().unwrap(),
                translated_port,
            },
        )
    }

    fn make_engine(rules: Vec<NatRule>) -> Arc<NatEngine> {
        let nat_rules = Arc::new(NatRules::new(rules));
        let engine = NatEngine::new(Some(nat_rules), HashMap::new());
        let proto = Arc::new(ProtoRegistry::new());
        let ct = Arc::new(Conntrack::new(proto, ConntrackConfig::default()));
        engine.attach_conntrack(&ct);
        engine
    }

    fn make_entry(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Arc<ConntrackEntry> {
        Arc::new(ConntrackEntry::new(
            1,
            FlowTuple { src_ip, src_port, dst_ip, dst_port, zone: 0, protocol: Protocol::Tcp },
            ProtoState::Tcp(TcpProtoState::default()),
            Duration::from_secs(300),
            0,
        ))
    }

    fn tcp_packet(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Vec<u8> {
        let IpAddr::V4(src) = src_ip else { panic!("test packet only supports IPv4") };
        let IpAddr::V4(dst) = dst_ip else { panic!("test packet only supports IPv4") };
        let mut raw = Vec::new();

        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4(src.octets(), dst.octets(), 64)
            .tcp(src_port, dst_port, 1, 65535)
            .write(&mut raw, b"hello")
            .unwrap();

        raw
    }

    fn packet_tuple(packet: &[u8]) -> FlowTuple {
        crate::nat::packet::parse_flow_tuple_from_ethernet(packet).unwrap()
    }

    #[test]
    fn dnat_with_translated_port_does_not_lease_in_port_store() {
        let engine = make_engine(vec![
            dnat_rule("d1", "203.0.113.10/32", "10.0.0.10", Some(80)),
        ]);

        let ct = make_entry(ip(192,168,1,100), 50000, ip(203,0,113,10), 8080);
        let range = NatRange::single_ip_port(ip(10,0,0,10), 80);
        let candidate = engine.allocate_unique_tuple(&ct, ManipType::Destination, &range, Protocol::Tcp, 0).unwrap();

        assert_eq!(candidate.port, Some(80));
        assert!(candidate.alloc_ip.is_none(), "DNAT fixed port must not lease in PortStore");
        assert!(candidate.alloc_port.is_none());
    }

    #[test]
    fn dnat_fixed_port_allows_multiple_concurrent_connections() {
        let engine = make_engine(vec![
            dnat_rule("d1", "203.0.113.10/32", "10.0.0.10", Some(80)),
        ]);

        let range = NatRange::single_ip_port(ip(10,0,0,10), 80);

        for i in 0..100u16 {
            let ct = make_entry(ip(192,168,1, (i % 254 + 1) as u8), 50000 + i, ip(203,0,113,10), 8080);
            let candidate = engine.allocate_unique_tuple(&ct, ManipType::Destination, &range, Protocol::Tcp, i as u64).unwrap();
            assert_eq!(candidate.port, Some(80));
        }

        assert!(!engine.port_store().is_leased(ip(10,0,0,10), Protocol::Tcp, 80));
    }

    #[test]
    fn pat_fixed_port_allows_multiple_concurrent_connections() {
        let engine = make_engine(vec![
            pat_rule("p1", "203.0.113.10", 8080, "10.0.0.10", 80),
        ]);

        let range = NatRange::single_ip_port(ip(10,0,0,10), 80);

        for i in 0..50u16 {
            let ct = make_entry(ip(192,168,1,100), 50000 + i, ip(203,0,113,10), 8080);
            let candidate = engine.allocate_unique_tuple(&ct, ManipType::Destination, &range, Protocol::Tcp, i as u64).unwrap();
            assert_eq!(candidate.port, Some(80));
        }
    }

    #[test]
    fn dnat_without_translated_port_uses_original_dst_port() {
        let engine = make_engine(vec![
            dnat_rule("d1", "203.0.113.0/24", "10.0.0.10", None),
        ]);

        let ct = make_entry(ip(192,168,1,100), 50000, ip(203,0,113,10), 443);

        let action = NatAction::Dnat {
            dst_cidr: "203.0.113.0/24".parse().unwrap(),
            translated_ip: ip(10,0,0,10),
            translated_port: None,
        };

        let range = engine.range_from_action(&action, None, &ct).unwrap();
        assert_eq!(range.min_port, 443);
        assert_eq!(range.max_port, 443);
    }

    #[test]
    fn dnat_with_translated_port_uses_that_port_in_range() {
        let engine = make_engine(vec![
            dnat_rule("d1", "203.0.113.0/24", "10.0.0.10", Some(80)),
        ]);

        let ct = make_entry(ip(192,168,1,100), 50000, ip(203,0,113,10), 8080);

        let action = NatAction::Dnat {
            dst_cidr: "203.0.113.0/24".parse().unwrap(),
            translated_ip: ip(10,0,0,10),
            translated_port: Some(80),
        };

        let range = engine.range_from_action(&action, None, &ct).unwrap();
        assert_eq!(range.min_port, 80);
        assert_eq!(range.max_port, 80);
    }

    #[test]
    fn reverse_snat_applies_in_prerouting() {
        let engine = make_engine(vec![
            snat_rule("s1", "192.168.10.0/24", "192.168.20.100"),
        ]);
        let ct = make_entry(ip(192,168,10,10), 40000, ip(192,168,20,10), 9999);

        let mut original = tcp_packet(ip(192,168,10,10), 40000, ip(192,168,20,10), 9999);
        assert!(matches!(
            engine.postrouting(&mut original, &ct, CtInfo::New, "eth2", None),
            NatOutcome::Created { .. }
        ));
        assert_eq!(
            packet_tuple(&original),
            FlowTuple::new(ip(192,168,20,100), 40000, ip(192,168,20,10), 9999, Protocol::Tcp),
        );

        let mut reply = tcp_packet(ip(192,168,20,10), 9999, ip(192,168,20,100), 40000);
        assert!(matches!(
            engine.prerouting(&mut reply, &ct, CtInfo::Established, "eth2", None),
            NatOutcome::AppliedExisting { .. }
        ));
        assert_eq!(
            packet_tuple(&reply),
            FlowTuple::new(ip(192,168,20,10), 9999, ip(192,168,10,10), 40000, Protocol::Tcp),
        );
    }

    #[test]
    fn source_nat_postrouting_is_idempotent_for_translated_original() {
        let engine = make_engine(vec![
            snat_rule("s1", "192.168.10.0/24", "192.168.20.100"),
        ]);
        let ct = make_entry(ip(192,168,10,10), 40000, ip(192,168,20,10), 9999);
        let mut packet = tcp_packet(ip(192,168,10,10), 40000, ip(192,168,20,10), 9999);

        assert!(matches!(
            engine.postrouting(&mut packet, &ct, CtInfo::New, "eth2", None),
            NatOutcome::Created { .. }
        ));
        assert_eq!(
            packet_tuple(&packet),
            FlowTuple::new(ip(192,168,20,100), 40000, ip(192,168,20,10), 9999, Protocol::Tcp),
        );

        assert!(matches!(
            engine.postrouting(&mut packet, &ct, CtInfo::New, "eth2", None),
            NatOutcome::AppliedExisting { .. }
        ));
        assert_eq!(
            packet_tuple(&packet),
            FlowTuple::new(ip(192,168,20,100), 40000, ip(192,168,20,10), 9999, Protocol::Tcp),
        );
    }

    #[test]
    fn dnat_reply_applies_in_postrouting() {
        let engine = make_engine(vec![
            dnat_rule("d1", "192.168.20.200/32", "192.168.20.10", Some(80)),
        ]);
        let ct = make_entry(ip(192,168,10,10), 40000, ip(192,168,20,200), 443);

        let mut original = tcp_packet(ip(192,168,10,10), 40000, ip(192,168,20,200), 443);
        assert!(matches!(
            engine.prerouting(&mut original, &ct, CtInfo::New, "eth1", None),
            NatOutcome::Created { .. }
        ));
        assert_eq!(
            packet_tuple(&original),
            FlowTuple::new(ip(192,168,10,10), 40000, ip(192,168,20,10), 80, Protocol::Tcp),
        );

        assert!(matches!(
            engine.postrouting(&mut original, &ct, CtInfo::New, "eth2", None),
            NatOutcome::NoMatch
        ));
        assert_eq!(
            packet_tuple(&original),
            FlowTuple::new(ip(192,168,10,10), 40000, ip(192,168,20,10), 80, Protocol::Tcp),
        );

        let mut reply = tcp_packet(ip(192,168,20,10), 80, ip(192,168,10,10), 40000);
        assert!(matches!(
            engine.prerouting(&mut reply, &ct, CtInfo::Established, "eth2", None),
            NatOutcome::NoMatch
        ));
        assert_eq!(
            packet_tuple(&reply),
            FlowTuple::new(ip(192,168,20,10), 80, ip(192,168,10,10), 40000, Protocol::Tcp),
        );

        assert!(matches!(
            engine.postrouting(&mut reply, &ct, CtInfo::Established, "eth1", None),
            NatOutcome::AppliedExisting { .. }
        ));
        assert_eq!(
            packet_tuple(&reply),
            FlowTuple::new(ip(192,168,20,200), 443, ip(192,168,10,10), 40000, Protocol::Tcp),
        );
    }
}
