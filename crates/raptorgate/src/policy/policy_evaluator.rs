use std::fmt::Display;
use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::data_plane::dns_inspection::types::DnssecStatus;
use crate::dpi::DpiContext;
use crate::identity::IdentityContext;
use crate::rule_tree::{
    ArrivalInfo, FieldValue, IpVer, MatchKind, Operation, Pattern, Port, Protocol, RuleTree, Step,
    TreeWalker, Verdict,
};

/// Kontekst DNS przekazywany do ewaluatora polityk — zawiera wyniki inspekcji DNS.
pub struct DnsEvalContext {
    /// Status walidacji DNSSEC dla domeny z zapytania DNS (wyznaczany leniwie przez
    /// [`DnssecProvider`][crate::data_plane::dns_inspection::dnssec::DnssecProvider]).
    pub dnssec_status: Option<DnssecStatus>,
}

pub(crate) struct PolicyEvalContext<'a, 'p> {
    pub packet: &'a SlicedPacket<'p>,
    pub arrival: &'a ArrivalInfo,
    pub dns: Option<&'a DnsEvalContext>,
    pub dpi: Option<&'a DpiContext>,
    /// Wynik IdentityLookupStage: doklejony do PacketContext przed NAT postrouting.
    /// `None` tylko gdy stage byl pominiety (brak src IP), w normalnym ruchu zawsze Some.
    pub identity: Option<&'a IdentityContext>,
}

pub struct PolicyEvaluator {
    rules: RuleTree,
    orphaned_verdict: Verdict,
}

impl PolicyEvaluator {
    pub(crate) fn new(rules: RuleTree, orphaned_verdict: Verdict) -> Self {
        Self {
            rules,
            orphaned_verdict,
        }
    }

    pub(crate) fn evaluate(&self, ctx: PolicyEvalContext<'_, '_>) -> Verdict {
        let mut walker = TreeWalker::new(&self.rules);

        loop {
            match walker.current_step() {
                Step::NeedsMatch { kind, pattern } => {
                    let matched = Self::matches_kind(*kind, pattern, &ctx);
                    if let Step::Verdict(v) = walker.advance(matched) {
                        return v.clone();
                    }
                }
                Step::Verdict(v) => return v.clone(),
                Step::NoMatch => return self.orphaned_verdict.clone(),
            }
        }
    }

    fn matches_kind(kind: MatchKind, pattern: &Pattern, ctx: &PolicyEvalContext<'_, '_>) -> bool {
        // identity_group ma asymetryczna semantyke: regula trzyma jedna nazwe,
        // sesja ma liste, dopasowanie sprawdza przynaleznosc.
        if matches!(kind, MatchKind::IdentityGroup) {
            let groups = ctx
                .identity
                .and_then(|identity| identity.session.as_ref().map(|s| s.groups.as_slice()));
            return Self::pattern_matches_group(pattern, groups);
        }

        match Self::extract(kind, ctx) {
            Some(value) => Self::pattern_matches(pattern, &value),
            None => Self::missing_value_matches(kind, pattern),
        }
    }

    fn extract(kind: MatchKind, ctx: &PolicyEvalContext<'_, '_>) -> Option<FieldValue> {
        match kind {
            MatchKind::SrcIp => {
                let ipv4 = ctx.packet.net.as_ref()?.ipv4_ref()?;
                Some(FieldValue::Ip(
                    IpAddr::V4(ipv4.header().source_addr()).into(),
                ))
            }
            MatchKind::DstIp => {
                let ipv4 = ctx.packet.net.as_ref()?.ipv4_ref()?;
                Some(FieldValue::Ip(
                    IpAddr::V4(ipv4.header().destination_addr()).into(),
                ))
            }
            MatchKind::IpVer => {
                let ver = match &ctx.packet.net {
                    Some(NetSlice::Ipv4(_)) => IpVer::V4,
                    Some(NetSlice::Ipv6(_)) => IpVer::V6,
                    _ => return None,
                };
                Some(FieldValue::IpVer(ver))
            }
            MatchKind::Protocol => {
                let proto = match &ctx.packet.transport {
                    Some(TransportSlice::Tcp(_)) => Protocol::Tcp,
                    Some(TransportSlice::Udp(_)) => Protocol::Udp,
                    Some(TransportSlice::Icmpv4(_)) => Protocol::Icmp,
                    _ => return None,
                };
                Some(FieldValue::Protocol(proto))
            }
            MatchKind::AppProto => {
                let proto = ctx.dpi?.app_proto?;
                Some(FieldValue::AppProto(proto))
            }
            MatchKind::SrcPort => match &ctx.packet.transport {
                Some(TransportSlice::Tcp(tcp)) => {
                    Some(FieldValue::Port(Port::from(tcp.source_port())))
                }
                Some(TransportSlice::Udp(udp)) => {
                    Some(FieldValue::Port(Port::from(udp.source_port())))
                }
                _ => None,
            },
            MatchKind::DstPort => match &ctx.packet.transport {
                Some(TransportSlice::Tcp(tcp)) => {
                    Some(FieldValue::Port(Port::from(tcp.destination_port())))
                }
                Some(TransportSlice::Udp(udp)) => {
                    Some(FieldValue::Port(Port::from(udp.destination_port())))
                }
                _ => None,
            },
            MatchKind::Hour => Some(FieldValue::Hour(ctx.arrival.hour)),
            MatchKind::DayOfWeek => Some(FieldValue::DayOfWeek(ctx.arrival.day_of_week)),
            MatchKind::DnssecStatus => {
                let status = ctx.dns?.dnssec_status?;
                Some(FieldValue::DnssecStatus(status))
            }
            MatchKind::AuthState => {
                // Brak identity_ctx oznacza, ze stage byl pominiety, traktujemy jak Unknown.
                let state = ctx
                    .identity
                    .map(|identity| identity.auth_state)
                    .unwrap_or(crate::identity::AuthState::Unknown);
                Some(FieldValue::AuthState(state))
            }
            MatchKind::IdentityUser => ctx
                .identity
                .and_then(|identity| identity.session.as_ref())
                .map(|session| FieldValue::IdentityUser(session.username.clone())),
            // identity_group obsluzony w matches_kind, tu nie powinno trafic.
            MatchKind::IdentityGroup => None,
        }
    }

    fn missing_value_matches(kind: MatchKind, pattern: &Pattern) -> bool {
        match kind {
            MatchKind::AppProto | MatchKind::IdentityUser => Self::pattern_accepts_missing(pattern),
            _ => false,
        }
    }

    fn pattern_accepts_missing(pattern: &Pattern) -> bool {
        match pattern {
            Pattern::Wildcard => true,
            Pattern::Or(patterns) => patterns.iter().any(Self::pattern_accepts_missing),
            Pattern::And(patterns) => patterns.iter().all(Self::pattern_accepts_missing),
            _ => false,
        }
    }

    fn pattern_matches(pattern: &Pattern, value: &FieldValue) -> bool {
        match (pattern, value) {
            (Pattern::Wildcard, _) => true,

            (Pattern::Equal(field_value), value) => field_value == value,

            (Pattern::Comparison(op, FieldValue::Port(rhs)), FieldValue::Port(v)) => match op {
                Operation::Greater => v > rhs,
                Operation::Lesser => v < rhs,
                Operation::GreaterOrEqual => v >= rhs,
                Operation::LesserOrEqual => v <= rhs,
            },
            (Pattern::Comparison(op, FieldValue::Hour(rhs)), FieldValue::Hour(v)) => match op {
                Operation::Greater => v > rhs,
                Operation::Lesser => v < rhs,
                Operation::GreaterOrEqual => v >= rhs,
                Operation::LesserOrEqual => v <= rhs,
            },
            (Pattern::Comparison(op, FieldValue::DayOfWeek(rhs)), FieldValue::DayOfWeek(v)) => {
                match op {
                    Operation::Greater => v > rhs,
                    Operation::Lesser => v < rhs,
                    Operation::GreaterOrEqual => v >= rhs,
                    Operation::LesserOrEqual => v <= rhs,
                }
            }
            (Pattern::Comparison(_, _), _) => false,

            (Pattern::Or(patterns), _) => patterns.iter().any(|p| Self::pattern_matches(p, value)),
            (Pattern::And(patterns), _) => patterns.iter().all(|p| Self::pattern_matches(p, value)),
        }
    }

    // identity_group: regula trzyma jedna nazwe, sesja liste, dopasowanie po przynaleznosci.
    // Brak sesji => tylko Wildcard pasuje (analogicznie do AppProto bez DPI).
    fn pattern_matches_group(pattern: &Pattern, groups: Option<&[String]>) -> bool {
        match pattern {
            Pattern::Wildcard => true,
            Pattern::Equal(FieldValue::IdentityGroup(name)) => {
                groups.is_some_and(|gs| gs.iter().any(|g| g == name))
            }
            Pattern::Or(patterns) => patterns
                .iter()
                .any(|p| Self::pattern_matches_group(p, groups)),
            Pattern::And(patterns) => patterns
                .iter()
                .all(|p| Self::pattern_matches_group(p, groups)),
            // Comparison i Equal innego typu sa odrzucone w validate_for, defensywnie zwracamy false.
            _ => false,
        }
    }
}

impl Display for PolicyEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PolicyEvaluator {{ rules: {}, orphaned_verdict: {} }}",
            self.rules, self.orphaned_verdict
        )
    }
}

#[cfg(test)]
mod tests {
    use etherparse::{PacketBuilder, SlicedPacket};

    use super::*;
    use crate::dpi::{AppProto, DpiContext};
    use crate::rule_tree::{
        ArmEnd, ArrivalInfo, Hour, IpGlobbable, IpVer, MatchBuilder, Octet, Port, Protocol, Weekday,
    };

    type IP = IpGlobbable;

    // ── Packet helpers ────────────────────────────────────────

    fn tcp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(src_ip, dst_ip, 64)
            .tcp(src_port, dst_port, 0, 1024);
        let mut result = Vec::with_capacity(builder.size(0));
        builder.write(&mut result, &[]).unwrap();
        result
    }

    fn udp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(src_ip, dst_ip, 64)
            .udp(src_port, dst_port);
        let mut result = Vec::with_capacity(builder.size(0));
        builder.write(&mut result, &[]).unwrap();
        result
    }

    fn icmp_packet(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(src_ip, dst_ip, 64)
            .icmpv4_echo_request(0, 0);
        let mut result = Vec::with_capacity(builder.size(0));
        builder.write(&mut result, &[]).unwrap();
        result
    }

    fn ipv6_tcp_packet() -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv6([0; 16], [0; 16], 64)
            .tcp(0, 0, 0, 1024);
        let mut result = Vec::with_capacity(builder.size(0));
        builder.write(&mut result, &[]).unwrap();
        result
    }

    /// Default test packet: 192.168.1.10 → 10.0.0.1, TCP 12345 → 80
    fn default_packet() -> Vec<u8> {
        tcp_packet([192, 168, 1, 10], [10, 0, 0, 1], 12345, 80)
    }

    /// Default test arrival: hour=14, day=Wednesday
    fn default_arrival() -> ArrivalInfo {
        ArrivalInfo {
            hour: Hour::try_from(14).unwrap(),
            day_of_week: Weekday::Wed,
        }
    }

    fn eval(tree: RuleTree, raw: &[u8], arrival: &ArrivalInfo) -> Verdict {
        eval_with_dpi(tree, raw, arrival, None)
    }

    fn eval_with_dpi(
        tree: RuleTree,
        raw: &[u8],
        arrival: &ArrivalInfo,
        dpi: Option<&DpiContext>,
    ) -> Verdict {
        eval_with_identity(tree, raw, arrival, dpi, None)
    }

    fn eval_with_identity(
        tree: RuleTree,
        raw: &[u8],
        arrival: &ArrivalInfo,
        dpi: Option<&DpiContext>,
        identity: Option<&IdentityContext>,
    ) -> Verdict {
        let sliced = SlicedPacket::from_ethernet(raw).unwrap();
        let evaluator = PolicyEvaluator::new(tree, Verdict::Drop);
        evaluator.evaluate(PolicyEvalContext {
            packet: &sliced,
            arrival,
            dns: None,
            dpi,
            identity,
        })
    }

    // ── Wildcard ──────────────────────────────────────────────

    #[test]
    fn wildcard_always_matches() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Wildcard,
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    // ── Equal: IP version ─────────────────────────────────────

    #[test]
    fn equal_ip_ver_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IpVer,
                Pattern::Equal(FieldValue::IpVer(IpVer::V4)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn equal_ip_ver_no_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IpVer,
                Pattern::Equal(FieldValue::IpVer(IpVer::V6)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Equal: Protocol ───────────────────────────────────────

    #[test]
    fn equal_protocol_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    #[test]
    fn equal_protocol_no_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    #[test]
    fn equal_app_proto_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::AppProto,
                Pattern::Equal(FieldValue::AppProto(AppProto::Http)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let dpi = DpiContext {
            app_proto: Some(AppProto::Http),
            ..Default::default()
        };
        assert_eq!(
            eval_with_dpi(tree, &default_packet(), &default_arrival(), Some(&dpi)),
            Verdict::Allow
        );
    }

    #[test]
    fn equal_app_proto_no_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::AppProto,
                Pattern::Equal(FieldValue::AppProto(AppProto::Http)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let dpi = DpiContext {
            app_proto: Some(AppProto::Tls),
            ..Default::default()
        };
        assert_eq!(
            eval_with_dpi(tree, &default_packet(), &default_arrival(), Some(&dpi)),
            Verdict::Drop
        );
    }

    #[test]
    fn equal_app_proto_without_dpi_no_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::AppProto,
                Pattern::Equal(FieldValue::AppProto(AppProto::Http)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval_with_dpi(tree, &default_packet(), &default_arrival(), None),
            Verdict::Drop
        );
    }

    #[test]
    fn wildcard_app_proto_without_dpi_matches() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::AppProto,
                Pattern::Wildcard,
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval_with_dpi(tree, &default_packet(), &default_arrival(), None),
            Verdict::Allow
        );
    }

    // ── Equal: Src IP ─────────────────────────────────────────

    #[test]
    fn equal_src_ip_match() {
        let ip = IP::new([
            Octet::Value(192),
            Octet::Value(168),
            Octet::Value(1),
            Octet::Value(10),
        ]);
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Equal(FieldValue::Ip(ip)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn equal_src_ip_no_match() {
        let ip = IP::new([
            Octet::Value(10),
            Octet::Value(10),
            Octet::Value(10),
            Octet::Value(10),
        ]);
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Equal(FieldValue::Ip(ip)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Equal: Dst IP ─────────────────────────────────────────

    #[test]
    fn equal_dst_ip_match() {
        let ip = IP::new([
            Octet::Value(10),
            Octet::Value(0),
            Octet::Value(0),
            Octet::Value(1),
        ]);
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DstIp,
                Pattern::Equal(FieldValue::Ip(ip)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    // ── Equal: Src Port ───────────────────────────────────────

    #[test]
    fn equal_src_port_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcPort,
                Pattern::Equal(FieldValue::Port(Port::from(12345))),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn equal_src_port_no_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcPort,
                Pattern::Equal(FieldValue::Port(Port::from(9999))),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Equal: Dst Port ───────────────────────────────────────

    #[test]
    fn equal_dst_port_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::Equal(FieldValue::Port(Port::from(80))),
                ArmEnd::Verdict(Verdict::AllowWarn("dst port is 80".into())),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::AllowWarn("dst port is 80".into())
        );
    }

    // ── Equal: Hour ───────────────────────────────────────────

    #[test]
    fn equal_hour_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Hour,
                Pattern::Equal(FieldValue::Hour(Hour::try_from(14).unwrap())),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn equal_hour_no_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Hour,
                Pattern::Equal(FieldValue::Hour(Hour::try_from(3).unwrap())),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Equal: DayOfWeek ──────────────────────────────────────

    #[test]
    fn equal_day_of_week_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DayOfWeek,
                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    #[test]
    fn equal_day_of_week_no_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DayOfWeek,
                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Glob: IP with wildcards ───────────────────────────────

    #[test]
    fn glob_src_ip_wildcard_octets() {
        let pat_ip = IP::new([Octet::Value(192), Octet::Value(168), Octet::Any, Octet::Any]);
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Equal(FieldValue::Ip(pat_ip)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn glob_src_ip_mismatch() {
        let pat_ip = IP::new([Octet::Value(10), Octet::Value(10), Octet::Any, Octet::Any]);
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Equal(FieldValue::Ip(pat_ip)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    #[test]
    fn glob_dst_ip_wildcard_octets() {
        let pat_ip = IP::new([Octet::Value(10), Octet::Any, Octet::Any, Octet::Any]);
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DstIp,
                Pattern::Equal(FieldValue::Ip(pat_ip)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    #[test]
    fn range_dst_port_below() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::And(vec![
                    Pattern::Comparison(
                        Operation::GreaterOrEqual,
                        FieldValue::Port(Port::from(81)),
                    ),
                    Pattern::Comparison(
                        Operation::LesserOrEqual,
                        FieldValue::Port(Port::from(443)),
                    ),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // dst_port = 80, not in [81, 443]
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    #[test]
    fn range_dst_port_exact_boundary() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::And(vec![
                    Pattern::Comparison(
                        Operation::GreaterOrEqual,
                        FieldValue::Port(Port::from(80)),
                    ),
                    Pattern::Comparison(Operation::LesserOrEqual, FieldValue::Port(Port::from(80))),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn range_src_port_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcPort,
                Pattern::And(vec![
                    Pattern::Comparison(
                        Operation::GreaterOrEqual,
                        FieldValue::Port(Port::from(10000)),
                    ),
                    Pattern::Comparison(
                        Operation::LesserOrEqual,
                        FieldValue::Port(Port::from(20000)),
                    ),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // src_port = 12345
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    // ── Range: Hour ───────────────────────────────────────────

    #[test]
    fn range_hour_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Hour,
                Pattern::And(vec![
                    Pattern::Comparison(
                        Operation::GreaterOrEqual,
                        FieldValue::Hour(Hour::try_from(9).unwrap()),
                    ),
                    Pattern::Comparison(
                        Operation::LesserOrEqual,
                        FieldValue::Hour(Hour::try_from(17).unwrap()),
                    ),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // hour = 14, in [9, 17]
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn range_hour_outside() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Hour,
                Pattern::And(vec![
                    Pattern::Comparison(
                        Operation::GreaterOrEqual,
                        FieldValue::Hour(Hour::try_from(15).unwrap()),
                    ),
                    Pattern::Comparison(
                        Operation::LesserOrEqual,
                        FieldValue::Hour(Hour::try_from(23).unwrap()),
                    ),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // hour = 14, not in [15, 23]
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Comparison: Port ──────────────────────────────────────

    #[test]
    fn comparison_dst_port_greater() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(79))),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // dst_port = 80 > 79
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn comparison_dst_port_greater_fail() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(80))),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // dst_port = 80, not > 80
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    #[test]
    fn comparison_dst_port_greater_or_equal() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::Comparison(Operation::GreaterOrEqual, FieldValue::Port(Port::from(80))),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn comparison_dst_port_lesser() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::Comparison(Operation::Lesser, FieldValue::Port(Port::from(81))),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // dst_port = 80 < 81
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn comparison_dst_port_lesser_or_equal() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::Comparison(Operation::LesserOrEqual, FieldValue::Port(Port::from(80))),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    // ── Comparison: Hour ──────────────────────────────────────

    #[test]
    fn comparison_hour_greater() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Hour,
                Pattern::Comparison(
                    Operation::Greater,
                    FieldValue::Hour(Hour::try_from(10).unwrap()),
                ),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // hour = 14 > 10
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn comparison_hour_lesser_fail() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Hour,
                Pattern::Comparison(
                    Operation::Lesser,
                    FieldValue::Hour(Hour::try_from(10).unwrap()),
                ),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // hour = 14, not < 10
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Comparison: DayOfWeek ─────────────────────────────────

    #[test]
    fn comparison_day_of_week_greater_or_equal() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DayOfWeek,
                Pattern::Comparison(
                    Operation::GreaterOrEqual,
                    FieldValue::DayOfWeek(Weekday::Mon),
                ),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // Wed >= Mon
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn comparison_day_of_week_lesser() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DayOfWeek,
                Pattern::Comparison(Operation::Lesser, FieldValue::DayOfWeek(Weekday::Fri)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // Wed < Fri
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn comparison_day_of_week_lesser_fail() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DayOfWeek,
                Pattern::Comparison(Operation::Lesser, FieldValue::DayOfWeek(Weekday::Mon)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // Wed not < Mon
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Or ────────────────────────────────────────────────────

    #[test]
    fn or_protocol_matches_first() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Or(vec![
                    Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                    Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn or_protocol_matches_second() {
        let raw = udp_packet([192, 168, 1, 10], [10, 0, 0, 1], 12345, 80);
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Or(vec![
                    Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                    Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(eval(tree, &raw, &default_arrival()), Verdict::Allow);
    }

    #[test]
    fn or_protocol_no_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Or(vec![
                    Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
                    Pattern::Equal(FieldValue::Protocol(Protocol::Icmp)),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // packet is Tcp
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    #[test]
    fn or_day_of_week() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DayOfWeek,
                Pattern::Or(vec![
                    Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
                    Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)),
                    Pattern::Equal(FieldValue::DayOfWeek(Weekday::Fri)),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn combined_and_or_allow() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcPort,
                Pattern::Or(vec![
                    Pattern::And(vec![
                        Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(80))),
                        Pattern::Comparison(Operation::Lesser, FieldValue::Port(Port::from(90))),
                    ]),
                    Pattern::Equal(FieldValue::Port(Port::from(12345))),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn combined_and_or_allow_in_nested() {
        let raw = tcp_packet([192, 168, 1, 10], [10, 0, 0, 1], 81, 80);
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcPort,
                Pattern::Or(vec![
                    Pattern::And(vec![
                        Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(80))),
                        Pattern::Comparison(Operation::Lesser, FieldValue::Port(Port::from(90))),
                    ]),
                    Pattern::Equal(FieldValue::Port(Port::from(12345))),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(eval(tree, &raw, &default_arrival()), Verdict::Allow);
    }

    #[test]
    fn combined_and_or_deny() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcPort,
                Pattern::Or(vec![
                    Pattern::And(vec![
                        Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(80))),
                        Pattern::Comparison(Operation::Lesser, FieldValue::Port(Port::from(90))),
                    ]),
                    Pattern::Equal(FieldValue::Port(Port::from(100))),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    #[test]
    fn and_day_of_week() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DayOfWeek,
                Pattern::And(vec![
                    Pattern::Comparison(Operation::Greater, FieldValue::DayOfWeek(Weekday::Tue)),
                    Pattern::Comparison(Operation::Lesser, FieldValue::DayOfWeek(Weekday::Thu)),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn and_day_of_week_invalid() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::DayOfWeek,
                Pattern::And(vec![
                    Pattern::Comparison(Operation::Greater, FieldValue::DayOfWeek(Weekday::Tue)),
                    Pattern::Comparison(Operation::Lesser, FieldValue::DayOfWeek(Weekday::Thu)),
                    Pattern::Equal(FieldValue::DayOfWeek(Weekday::Fri)),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Multiple arms (fallthrough to second arm) ─────────────

    #[test]
    fn multiple_arms_first_matches() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .arm(
                Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn multiple_arms_second_matches() {
        let raw = udp_packet([192, 168, 1, 10], [10, 0, 0, 1], 12345, 80);
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .arm(
                Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(eval(tree, &raw, &default_arrival()), Verdict::Drop);
    }

    #[test]
    fn multiple_arms_none_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .arm(
                Pattern::Equal(FieldValue::Protocol(Protocol::Icmp)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        // packet is Tcp
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Port-less protocol returns None for port extraction ───

    #[test]
    fn icmp_frame_port_extraction_returns_none() {
        let raw = icmp_packet([192, 168, 1, 10], [10, 0, 0, 1]);
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcPort,
                Pattern::Equal(FieldValue::Port(Port::from(80))),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // extract returns None → evaluate returns Drop
        assert_eq!(eval(tree, &raw, &default_arrival()), Verdict::Drop);
    }

    // ── Nested tree (larger integration-style test) ───────────

    #[test]
    fn nested_ipver_then_protocol_then_dst_port_allow() {
        // Match V4 → match Tcp → dst_port in [0, 1024] → Allow
        //                       → dst_port > 1024       → AllowWarn
        //           → match Udp → Wildcard               → Drop
        // Match V6 → Drop
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IpVer,
                Pattern::Equal(FieldValue::IpVer(IpVer::V4)),
                ArmEnd::Match(
                    MatchBuilder::with_arm(
                        MatchKind::Protocol,
                        Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                        ArmEnd::Match(
                            MatchBuilder::with_arm(
                                MatchKind::DstPort,
                                Pattern::And(vec![
                                    Pattern::Comparison(
                                        Operation::GreaterOrEqual,
                                        FieldValue::Port(Port::from(0)),
                                    ),
                                    Pattern::Comparison(
                                        Operation::LesserOrEqual,
                                        FieldValue::Port(Port::from(1024)),
                                    ),
                                ]),
                                ArmEnd::Verdict(Verdict::Allow),
                            )
                            .arm(
                                Pattern::Comparison(
                                    Operation::Greater,
                                    FieldValue::Port(Port::from(1024)),
                                ),
                                ArmEnd::Verdict(Verdict::AllowWarn("high dst port".into())),
                            )
                            .build()
                            .unwrap(),
                        ),
                    )
                    .arm(
                        Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
                        ArmEnd::Verdict(Verdict::Drop),
                    )
                    .build()
                    .unwrap(),
                ),
            )
            .arm(
                Pattern::Equal(FieldValue::IpVer(IpVer::V6)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );

        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn nested_v4_tcp_high_port_allow_warn() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IpVer,
                Pattern::Equal(FieldValue::IpVer(IpVer::V4)),
                ArmEnd::Match(
                    MatchBuilder::with_arm(
                        MatchKind::Protocol,
                        Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                        ArmEnd::Match(
                            MatchBuilder::with_arm(
                                MatchKind::DstPort,
                                Pattern::And(vec![
                                    Pattern::Comparison(
                                        Operation::GreaterOrEqual,
                                        FieldValue::Port(Port::from(0)),
                                    ),
                                    Pattern::Comparison(
                                        Operation::LesserOrEqual,
                                        FieldValue::Port(Port::from(1024)),
                                    ),
                                ]),
                                ArmEnd::Verdict(Verdict::Allow),
                            )
                            .arm(
                                Pattern::Comparison(
                                    Operation::Greater,
                                    FieldValue::Port(Port::from(1024)),
                                ),
                                ArmEnd::Verdict(Verdict::AllowWarn("high dst port".into())),
                            )
                            .build()
                            .unwrap(),
                        ),
                    )
                    .build()
                    .unwrap(),
                ),
            )
            .build()
            .unwrap(),
        );

        let raw = tcp_packet([192, 168, 1, 10], [10, 0, 0, 1], 12345, 8080);
        assert_eq!(
            eval(tree, &raw, &default_arrival()),
            Verdict::AllowWarn("high dst port".into())
        );
    }

    #[test]
    fn nested_v4_udp_drop() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IpVer,
                Pattern::Equal(FieldValue::IpVer(IpVer::V4)),
                ArmEnd::Match(
                    MatchBuilder::with_arm(
                        MatchKind::Protocol,
                        Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                        ArmEnd::Verdict(Verdict::Allow),
                    )
                    .arm(
                        Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
                        ArmEnd::Verdict(Verdict::Drop),
                    )
                    .build()
                    .unwrap(),
                ),
            )
            .build()
            .unwrap(),
        );

        let raw = udp_packet([192, 168, 1, 10], [10, 0, 0, 1], 12345, 80);
        assert_eq!(eval(tree, &raw, &default_arrival()), Verdict::Drop);
    }

    #[test]
    fn nested_v6_drop() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IpVer,
                Pattern::Equal(FieldValue::IpVer(IpVer::V4)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .arm(
                Pattern::Equal(FieldValue::IpVer(IpVer::V6)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );

        assert_eq!(
            eval(tree, &ipv6_tcp_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    // ── Nested: IP glob + hour range + day check ──────────────

    #[test]
    fn nested_glob_ip_then_hour_range_then_day() {
        // SrcIp glob 192.168.*.* → Hour in [8,18] → DayOfWeek == Wed → Allow
        //                                          → otherwise       → Drop
        //                         → Hour outside   → AllowWarn
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Equal(FieldValue::Ip(IP::new([
                    Octet::Value(192),
                    Octet::Value(168),
                    Octet::Any,
                    Octet::Any,
                ]))),
                ArmEnd::Match(
                    MatchBuilder::with_arm(
                        MatchKind::Hour,
                        Pattern::And(vec![
                            Pattern::Comparison(
                                Operation::GreaterOrEqual,
                                FieldValue::Hour(Hour::try_from(8).unwrap()),
                            ),
                            Pattern::Comparison(
                                Operation::LesserOrEqual,
                                FieldValue::Hour(Hour::try_from(18).unwrap()),
                            ),
                        ]),
                        ArmEnd::Match(
                            MatchBuilder::with_arm(
                                MatchKind::DayOfWeek,
                                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)),
                                ArmEnd::Verdict(Verdict::Allow),
                            )
                            .arm(Pattern::Wildcard, ArmEnd::Verdict(Verdict::Drop))
                            .build()
                            .unwrap(),
                        ),
                    )
                    .arm(
                        Pattern::Wildcard,
                        ArmEnd::Verdict(Verdict::AllowWarn("hour outside range".into())),
                    )
                    .build()
                    .unwrap(),
                ),
            )
            .build()
            .unwrap(),
        );

        // src=192.168.1.10, hour=14 (in [8,18]), day=Wed → Allow
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Allow
        );
    }

    #[test]
    fn nested_glob_ip_hour_in_range_wrong_day_drops() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Equal(FieldValue::Ip(IP::new([
                    Octet::Value(192),
                    Octet::Value(168),
                    Octet::Any,
                    Octet::Any,
                ]))),
                ArmEnd::Match(
                    MatchBuilder::with_arm(
                        MatchKind::Hour,
                        Pattern::And(vec![
                            Pattern::Comparison(
                                Operation::GreaterOrEqual,
                                FieldValue::Hour(Hour::try_from(8).unwrap()),
                            ),
                            Pattern::Comparison(
                                Operation::LesserOrEqual,
                                FieldValue::Hour(Hour::try_from(18).unwrap()),
                            ),
                        ]),
                        ArmEnd::Match(
                            MatchBuilder::with_arm(
                                MatchKind::DayOfWeek,
                                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
                                ArmEnd::Verdict(Verdict::Allow),
                            )
                            .arm(Pattern::Wildcard, ArmEnd::Verdict(Verdict::Drop))
                            .build()
                            .unwrap(),
                        ),
                    )
                    .build()
                    .unwrap(),
                ),
            )
            .build()
            .unwrap(),
        );

        // day=Wed, but arm only allows Mon → falls to wildcard → Drop
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::Drop
        );
    }

    #[test]
    fn nested_glob_ip_hour_outside_range_drop_warn() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Equal(FieldValue::Ip(IP::new([
                    Octet::Value(192),
                    Octet::Value(168),
                    Octet::Any,
                    Octet::Any,
                ]))),
                ArmEnd::Match(
                    MatchBuilder::with_arm(
                        MatchKind::Hour,
                        Pattern::And(vec![
                            Pattern::Comparison(
                                Operation::GreaterOrEqual,
                                FieldValue::Hour(Hour::try_from(8).unwrap()),
                            ),
                            Pattern::Comparison(
                                Operation::LesserOrEqual,
                                FieldValue::Hour(Hour::try_from(12).unwrap()),
                            ),
                        ]),
                        ArmEnd::Verdict(Verdict::Allow),
                    )
                    .arm(
                        Pattern::Wildcard,
                        ArmEnd::Verdict(Verdict::DropWarn("hour outside range".into())),
                    )
                    .build()
                    .unwrap(),
                ),
            )
            .build()
            .unwrap(),
        );

        // hour=14, not in [8,12] → falls to wildcard → DropWarn
        assert_eq!(
            eval(tree, &default_packet(), &default_arrival()),
            Verdict::DropWarn("hour outside range".into())
        );
    }

    // Identity matchery: auth_state / identity_user / identity_group (Issue 6).

    use crate::identity::{AuthState, IdentitySession};
    use std::time::{Duration, UNIX_EPOCH};

    fn authenticated_session(username: &str, groups: Vec<&str>) -> IdentitySession {
        IdentitySession {
            session_id: "sess-1".into(),
            identity_user_id: format!("user-{username}"),
            username: username.into(),
            client_ip: "192.168.10.10".parse().unwrap(),
            authenticated_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            expires_at: UNIX_EPOCH + Duration::from_secs(1_700_003_600),
            groups: groups.into_iter().map(String::from).collect(),
        }
    }

    fn authenticated_ctx(session: IdentitySession) -> IdentityContext {
        IdentityContext::authenticated("192.168.10.10".parse().unwrap(), session)
    }

    fn unknown_ctx() -> IdentityContext {
        IdentityContext::unknown("192.168.10.10".parse().unwrap())
    }

    #[test]
    fn equal_auth_state_authenticated_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::AuthState,
                Pattern::Equal(FieldValue::AuthState(AuthState::Authenticated)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let ctx = authenticated_ctx(authenticated_session("alice", vec![]));
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Allow
        );
    }

    #[test]
    fn equal_auth_state_unknown_when_no_session() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::AuthState,
                Pattern::Equal(FieldValue::AuthState(AuthState::Unknown)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        let ctx = unknown_ctx();
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Drop
        );
    }

    #[test]
    fn equal_auth_state_no_identity_ctx_treated_as_unknown() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::AuthState,
                Pattern::Equal(FieldValue::AuthState(AuthState::Unknown)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, None),
            Verdict::Drop
        );
    }

    #[test]
    fn equal_identity_user_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IdentityUser,
                Pattern::Equal(FieldValue::IdentityUser("alice".into())),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let ctx = authenticated_ctx(authenticated_session("alice", vec![]));
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Allow
        );
    }

    #[test]
    fn equal_identity_user_no_match_for_different_user() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IdentityUser,
                Pattern::Equal(FieldValue::IdentityUser("alice".into())),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let ctx = authenticated_ctx(authenticated_session("bob", vec![]));
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Drop
        );
    }

    #[test]
    fn equal_identity_user_no_session_drops() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IdentityUser,
                Pattern::Equal(FieldValue::IdentityUser("alice".into())),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let ctx = unknown_ctx();
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Drop
        );
    }

    #[test]
    fn wildcard_identity_user_no_session_matches() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IdentityUser,
                Pattern::Wildcard,
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let ctx = unknown_ctx();
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Allow
        );
    }

    #[test]
    fn or_identity_user_matches_one_of() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IdentityUser,
                Pattern::Or(vec![
                    Pattern::Equal(FieldValue::IdentityUser("alice".into())),
                    Pattern::Equal(FieldValue::IdentityUser("bob".into())),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let ctx = authenticated_ctx(authenticated_session("bob", vec![]));
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Allow
        );
    }

    #[test]
    fn equal_identity_group_match_when_in_list() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IdentityGroup,
                Pattern::Equal(FieldValue::IdentityGroup("admins".into())),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let ctx = authenticated_ctx(authenticated_session("alice", vec!["admins", "users"]));
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Allow
        );
    }

    #[test]
    fn equal_identity_group_no_match_when_not_in_list() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IdentityGroup,
                Pattern::Equal(FieldValue::IdentityGroup("admins".into())),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let ctx = authenticated_ctx(authenticated_session("alice", vec!["users"]));
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Drop
        );
    }

    #[test]
    fn equal_identity_group_no_session_no_match() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IdentityGroup,
                Pattern::Equal(FieldValue::IdentityGroup("admins".into())),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let ctx = unknown_ctx();
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Drop
        );
    }

    #[test]
    fn or_identity_group_matches_one_of() {
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::IdentityGroup,
                Pattern::Or(vec![
                    Pattern::Equal(FieldValue::IdentityGroup("admins".into())),
                    Pattern::Equal(FieldValue::IdentityGroup("auditors".into())),
                ]),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        let ctx = authenticated_ctx(authenticated_session("alice", vec!["users", "auditors"]));
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&ctx)),
            Verdict::Allow
        );
    }

    #[test]
    fn nested_auth_state_and_identity_user() {
        // Tylko zalogowani uzytkownicy: alice => Allow, kazdy inny uwierzytelniony => Drop.
        let tree = RuleTree::new(
            MatchBuilder::with_arm(
                MatchKind::AuthState,
                Pattern::Equal(FieldValue::AuthState(AuthState::Authenticated)),
                ArmEnd::Match(
                    MatchBuilder::with_arm(
                        MatchKind::IdentityUser,
                        Pattern::Equal(FieldValue::IdentityUser("alice".into())),
                        ArmEnd::Verdict(Verdict::Allow),
                    )
                    .arm(Pattern::Wildcard, ArmEnd::Verdict(Verdict::Drop))
                    .build()
                    .unwrap(),
                ),
            )
            .arm(Pattern::Wildcard, ArmEnd::Verdict(Verdict::Drop))
            .build()
            .unwrap(),
        );

        let alice = authenticated_ctx(authenticated_session("alice", vec![]));
        assert_eq!(
            eval_with_identity(
                tree.clone(),
                &default_packet(),
                &default_arrival(),
                None,
                Some(&alice),
            ),
            Verdict::Allow
        );

        let bob = authenticated_ctx(authenticated_session("bob", vec![]));
        assert_eq!(
            eval_with_identity(tree, &default_packet(), &default_arrival(), None, Some(&bob)),
            Verdict::Drop
        );
    }
}
