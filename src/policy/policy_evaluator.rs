use std::fmt::Display;
use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::rule_tree::{
    ArrivalInfo, FieldValue, IpVer, MatchKind, Operation, Pattern, Port, Protocol, RuleTree, Step,
    TreeWalker, Verdict,
};

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

    pub(crate) fn evaluate(&self, packet: &SlicedPacket, arrival: &ArrivalInfo) -> Verdict {
        let mut walker = TreeWalker::new(&self.rules);

        loop {
            match walker.current_step() {
                Step::NeedsMatch { kind, pattern } => {
                    let Some(value) = Self::extract(*kind, packet, arrival) else {
                        walker.advance(false);
                        continue;
                    };
                    let matched = Self::pattern_matches(pattern, value);
                    if let Step::Verdict(v) = walker.advance(matched) {
                        return v.clone();
                    }
                }
                Step::Verdict(v) => return v.clone(),
                Step::NoMatch => return self.orphaned_verdict.clone(),
            }
        }
    }

    fn extract(
        kind: MatchKind,
        packet: &SlicedPacket,
        arrival: &ArrivalInfo,
    ) -> Option<FieldValue> {
        match kind {
            MatchKind::SrcIp => {
                let ipv4 = packet.net.as_ref()?.ipv4_ref()?;
                Some(FieldValue::Ip(
                    IpAddr::V4(ipv4.header().source_addr()).into(),
                ))
            }
            MatchKind::DstIp => {
                let ipv4 = packet.net.as_ref()?.ipv4_ref()?;
                Some(FieldValue::Ip(
                    IpAddr::V4(ipv4.header().destination_addr()).into(),
                ))
            }
            MatchKind::IpVer => {
                let ver = match &packet.net {
                    Some(NetSlice::Ipv4(_)) => IpVer::V4,
                    Some(NetSlice::Ipv6(_)) => IpVer::V6,
                    _ => return None,
                };
                Some(FieldValue::IpVer(ver))
            }
            MatchKind::Protocol => {
                let proto = match &packet.transport {
                    Some(TransportSlice::Tcp(_)) => Protocol::Tcp,
                    Some(TransportSlice::Udp(_)) => Protocol::Udp,
                    Some(TransportSlice::Icmpv4(_)) => Protocol::Icmp,
                    _ => return None,
                };
                Some(FieldValue::Protocol(proto))
            }
            MatchKind::SrcPort => match &packet.transport {
                Some(TransportSlice::Tcp(tcp)) => {
                    Some(FieldValue::Port(Port::from(tcp.source_port())))
                }
                Some(TransportSlice::Udp(udp)) => {
                    Some(FieldValue::Port(Port::from(udp.source_port())))
                }
                _ => None,
            },
            MatchKind::DstPort => match &packet.transport {
                Some(TransportSlice::Tcp(tcp)) => {
                    Some(FieldValue::Port(Port::from(tcp.destination_port())))
                }
                Some(TransportSlice::Udp(udp)) => {
                    Some(FieldValue::Port(Port::from(udp.destination_port())))
                }
                _ => None,
            },
            MatchKind::Hour => Some(FieldValue::Hour(arrival.hour)),
            MatchKind::DayOfWeek => Some(FieldValue::DayOfWeek(arrival.day_of_week)),
        }
    }

    fn pattern_matches(pattern: &Pattern, value: FieldValue) -> bool {
        match (pattern, value) {
            (Pattern::Wildcard, _) => true,

            (Pattern::Equal(field_value), value) => *field_value == value,

            (Pattern::Comparison(op, FieldValue::Port(rhs)), FieldValue::Port(v)) => match op {
                Operation::Greater => v > *rhs,
                Operation::Lesser => v < *rhs,
                Operation::GreaterOrEqual => v >= *rhs,
                Operation::LesserOrEqual => v <= *rhs,
            },
            (Pattern::Comparison(op, FieldValue::Hour(rhs)), FieldValue::Hour(v)) => match op {
                Operation::Greater => v > *rhs,
                Operation::Lesser => v < *rhs,
                Operation::GreaterOrEqual => v >= *rhs,
                Operation::LesserOrEqual => v <= *rhs,
            },
            (Pattern::Comparison(op, FieldValue::DayOfWeek(rhs)), FieldValue::DayOfWeek(v)) => {
                match op {
                    Operation::Greater => v > *rhs,
                    Operation::Lesser => v < *rhs,
                    Operation::GreaterOrEqual => v >= *rhs,
                    Operation::LesserOrEqual => v <= *rhs,
                }
            }
            (Pattern::Comparison(_, _), _) => false,

            (Pattern::Or(patterns), _) => patterns.iter().any(|p| Self::pattern_matches(p, value)),
            (Pattern::And(patterns), _) => patterns.iter().all(|p| Self::pattern_matches(p, value)),
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
        let sliced = SlicedPacket::from_ethernet(raw).unwrap();
        let evaluator = PolicyEvaluator::new(tree, Verdict::Drop);
        evaluator.evaluate(&sliced, arrival)
    }

    // ── Wildcard ──────────────────────────────────────────────

    #[test]
    fn wildcard_always_matches() {
        let tree = RuleTree::new(
            "wildcard".into(),
            "".into(),
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
            "ipver_eq".into(),
            "".into(),
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
            "ipver_eq_miss".into(),
            "".into(),
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
            "proto_eq".into(),
            "".into(),
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
            "proto_eq_miss".into(),
            "".into(),
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
            "srcip_eq".into(),
            "".into(),
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
            "srcip_eq_miss".into(),
            "".into(),
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
            "dstip_eq".into(),
            "".into(),
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
            "srcport_eq".into(),
            "".into(),
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
            "srcport_eq_miss".into(),
            "".into(),
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
            "dstport_eq".into(),
            "".into(),
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
            "hour_eq".into(),
            "".into(),
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
            "hour_eq_miss".into(),
            "".into(),
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
            "dow_eq".into(),
            "".into(),
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
            "dow_eq_miss".into(),
            "".into(),
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
            "glob_src".into(),
            "".into(),
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
            "glob_src_miss".into(),
            "".into(),
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
            "glob_dst".into(),
            "".into(),
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
            "range_port_miss".into(),
            "".into(),
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
            "range_port_boundary".into(),
            "".into(),
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
            "range_srcport".into(),
            "".into(),
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
            "range_hour".into(),
            "".into(),
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
            "range_hour_miss".into(),
            "".into(),
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
            "cmp_port_gt".into(),
            "".into(),
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
            "cmp_port_gt_fail".into(),
            "".into(),
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
            "cmp_port_ge".into(),
            "".into(),
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
            "cmp_port_lt".into(),
            "".into(),
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
            "cmp_port_le".into(),
            "".into(),
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
            "cmp_hour_gt".into(),
            "".into(),
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
            "cmp_hour_lt_fail".into(),
            "".into(),
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
            "cmp_dow_ge".into(),
            "".into(),
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
            "cmp_dow_lt".into(),
            "".into(),
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
            "cmp_dow_lt_fail".into(),
            "".into(),
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
            "or_proto".into(),
            "".into(),
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
            "or_proto_2nd".into(),
            "".into(),
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
            "or_proto_miss".into(),
            "".into(),
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
            "or_dow".into(),
            "".into(),
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
            "or_dow".into(),
            "".into(),
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
            "or_dow".into(),
            "".into(),
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
            "or_dow".into(),
            "".into(),
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
            "or_dow".into(),
            "".into(),
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
            "or_dow".into(),
            "".into(),
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
            "multi_arms_1st".into(),
            "".into(),
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
            "multi_arms_2nd".into(),
            "".into(),
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
            "multi_arms_none".into(),
            "".into(),
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
            "port_none".into(),
            "".into(),
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
            "nested".into(),
            "complex nested rule".into(),
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
            "nested_high".into(),
            "".into(),
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
            "nested_udp".into(),
            "".into(),
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
            "nested_v6".into(),
            "".into(),
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
            "nested_complex".into(),
            "glob+hour+day".into(),
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
            "nested_wrong_day".into(),
            "".into(),
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
            "nested_late_hour".into(),
            "".into(),
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
}
