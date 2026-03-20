use std::fmt::Display;

use crate::{
    frame::Frame,
    rule_tree::{FieldValue, MatchKind, Operation, Pattern, RuleTree, Step, TreeWalker, Verdict},
};

pub(crate) struct PolicyEvaluator {
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

    pub(crate) fn evaluate<T: Frame>(&self, frame: &T) -> Option<Verdict> {
        let context = PolicyContext {
            frame,
            allowed: false,
            warned: false,
        };
        let mut walker = TreeWalker::new(&self.rules);

        loop {
            match walker.current_step() {
                Step::NeedsMatch { kind, pattern } => {
                    let value = Self::extract(*kind, &context)?;
                    let matched = Self::pattern_matches(pattern, value);
                    if let Step::Verdict(v) = walker.advance(matched) {
                        return Some(v.clone());
                    }
                }
                Step::Verdict(v) => return Some(v.clone()),
                Step::NoMatch => return None,
            }
        }
    }

    fn extract<T: Frame>(kind: MatchKind, context: &PolicyContext<T>) -> Option<FieldValue> {
        let frame = context.frame;
        match kind {
            MatchKind::SrcIp => Some(FieldValue::Ip(frame.src_ip())),
            MatchKind::DstIp => Some(FieldValue::Ip(frame.dst_ip())),
            MatchKind::IpVer => Some(FieldValue::IpVer(frame.ip_ver())),
            MatchKind::DayOfWeek => Some(FieldValue::DayOfWeek(frame.day_of_week())),
            MatchKind::Hour => Some(FieldValue::Hour(frame.hour())),
            MatchKind::Protocol => Some(FieldValue::Protocol(frame.protocol())),
            MatchKind::SrcPort => frame.src_port().map(FieldValue::Port),
            MatchKind::DstPort => frame.dst_port().map(FieldValue::Port),
        }
    }

    fn pattern_matches(pattern: &Pattern, value: FieldValue) -> bool {
        match (pattern, value) {
            (Pattern::Wildcard, _) => true,

            (Pattern::Equal(field_value), value) => *field_value == value,

            (Pattern::Glob(FieldValue::Ip(pat_ip)), FieldValue::Ip(ip)) => *pat_ip == ip,
            (Pattern::Glob(_), _) => false,

            (Pattern::Range(FieldValue::Port(lo), FieldValue::Port(hi)), FieldValue::Port(v)) => {
                v >= *lo && v <= *hi
            }
            (Pattern::Range(FieldValue::Hour(lo), FieldValue::Hour(hi)), FieldValue::Hour(v)) => {
                v >= *lo && v <= *hi
            }
            (Pattern::Range(_, _), _) => false,

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
        }
    }
}

impl Display for PolicyEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PolicyEvaluator {{ rules: {}, orphaned_verdict: {} }}", self.rules, self.orphaned_verdict)
    }
}

struct PolicyContext<'a, T>
where
    T: Frame,
{
    frame: &'a T,
    allowed: bool,
    warned: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        frame::{Hour, IP, IpVer, Octet, Port, Protocol, Weekday},
        rule_tree::{ArmEnd, MatchBuilder},
    };

    struct DummyFrame {
        src_ip: IP,
        dst_ip: IP,
        ip_ver: IpVer,
        protocol: Protocol,
        src_port: Option<Port>,
        dst_port: Option<Port>,
        hour: Hour,
        day_of_week: Weekday,
    }

    impl DummyFrame {
        fn default_v4() -> Self {
            Self {
                src_ip: IP::new([
                    Octet::Value(192),
                    Octet::Value(168),
                    Octet::Value(1),
                    Octet::Value(10),
                ]),
                dst_ip: IP::new([
                    Octet::Value(10),
                    Octet::Value(0),
                    Octet::Value(0),
                    Octet::Value(1),
                ]),
                ip_ver: IpVer::V4,
                protocol: Protocol::Tcp,
                src_port: Some(Port::from(12345)),
                dst_port: Some(Port::from(80)),
                hour: Hour::try_from(14).unwrap(),
                day_of_week: Weekday::Wed,
            }
        }
    }

    impl Frame for DummyFrame {
        fn ip_ver(&self) -> IpVer {
            self.ip_ver
        }
        fn src_ip(&self) -> IP {
            self.src_ip
        }
        fn dst_ip(&self) -> IP {
            self.dst_ip
        }
        fn protocol(&self) -> Protocol {
            self.protocol
        }
        fn src_port(&self) -> Option<Port> {
            self.src_port
        }
        fn dst_port(&self) -> Option<Port> {
            self.dst_port
        }
        fn hour(&self) -> Hour {
            self.hour
        }
        fn day_of_week(&self) -> Weekday {
            self.day_of_week
        }
    }

    fn eval(tree: RuleTree, frame: &DummyFrame) -> Option<Verdict> {
        let evaluator = PolicyEvaluator::new(tree, Verdict::Drop);
        evaluator.evaluate(frame)
    }

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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Drop));
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
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
            eval(tree, &DummyFrame::default_v4()),
            Some(Verdict::AllowWarn("dst port is 80".into()))
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Drop));
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
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
                Pattern::Glob(FieldValue::Ip(pat_ip)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
    }

    #[test]
    fn glob_src_ip_mismatch() {
        let pat_ip = IP::new([Octet::Value(10), Octet::Value(10), Octet::Any, Octet::Any]);
        let tree = RuleTree::new(
            "glob_src_miss".into(),
            "".into(),
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Glob(FieldValue::Ip(pat_ip)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
    }

    #[test]
    fn glob_dst_ip_wildcard_octets() {
        let pat_ip = IP::new([Octet::Value(10), Octet::Any, Octet::Any, Octet::Any]);
        let tree = RuleTree::new(
            "glob_dst".into(),
            "".into(),
            MatchBuilder::with_arm(
                MatchKind::DstIp,
                Pattern::Glob(FieldValue::Ip(pat_ip)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Drop));
    }

    // ── Range: Port ───────────────────────────────────────────

    #[test]
    fn range_dst_port_inclusive_match() {
        let tree = RuleTree::new(
            "range_port".into(),
            "".into(),
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::Range(
                    FieldValue::Port(Port::from(70)),
                    FieldValue::Port(Port::from(90)),
                ),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // dst_port = 80, in [70, 90]
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
    }

    #[test]
    fn range_dst_port_below() {
        let tree = RuleTree::new(
            "range_port_miss".into(),
            "".into(),
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::Range(
                    FieldValue::Port(Port::from(81)),
                    FieldValue::Port(Port::from(443)),
                ),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // dst_port = 80, not in [81, 443]
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
    }

    #[test]
    fn range_dst_port_exact_boundary() {
        let tree = RuleTree::new(
            "range_port_boundary".into(),
            "".into(),
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::Range(
                    FieldValue::Port(Port::from(80)),
                    FieldValue::Port(Port::from(80)),
                ),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
    }

    #[test]
    fn range_src_port_match() {
        let tree = RuleTree::new(
            "range_srcport".into(),
            "".into(),
            MatchBuilder::with_arm(
                MatchKind::SrcPort,
                Pattern::Range(
                    FieldValue::Port(Port::from(10000)),
                    FieldValue::Port(Port::from(20000)),
                ),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // src_port = 12345
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
    }

    // ── Range: Hour ───────────────────────────────────────────

    #[test]
    fn range_hour_match() {
        let tree = RuleTree::new(
            "range_hour".into(),
            "".into(),
            MatchBuilder::with_arm(
                MatchKind::Hour,
                Pattern::Range(
                    FieldValue::Hour(Hour::try_from(9).unwrap()),
                    FieldValue::Hour(Hour::try_from(17).unwrap()),
                ),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // hour = 14, in [9, 17]
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
    }

    #[test]
    fn range_hour_outside() {
        let tree = RuleTree::new(
            "range_hour_miss".into(),
            "".into(),
            MatchBuilder::with_arm(
                MatchKind::Hour,
                Pattern::Range(
                    FieldValue::Hour(Hour::try_from(15).unwrap()),
                    FieldValue::Hour(Hour::try_from(23).unwrap()),
                ),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        );
        // hour = 14, not in [15, 23]
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
    }

    #[test]
    fn or_protocol_matches_second() {
        let mut frame = DummyFrame::default_v4();
        frame.protocol = Protocol::Udp;
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
        assert_eq!(eval(tree, &frame), Some(Verdict::Allow));
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
        // frame is Tcp
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
    }

    #[test]
    fn multiple_arms_second_matches() {
        let mut frame = DummyFrame::default_v4();
        frame.protocol = Protocol::Udp;
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
        assert_eq!(eval(tree, &frame), Some(Verdict::Drop));
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
        // frame is Tcp
        assert!(eval(tree, &DummyFrame::default_v4()).is_none());
    }

    // ── Port-less protocol returns None for port extraction ───

    #[test]
    fn icmp_frame_port_extraction_returns_none() {
        let mut frame = DummyFrame::default_v4();
        frame.protocol = Protocol::Icmp;
        frame.src_port = None;
        frame.dst_port = None;

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
        // extract returns None → evaluate returns None
        assert!(eval(tree, &frame).is_none());
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
                                Pattern::Range(
                                    FieldValue::Port(Port::from(0)),
                                    FieldValue::Port(Port::from(1024)),
                                ),
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

        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
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
                                Pattern::Range(
                                    FieldValue::Port(Port::from(0)),
                                    FieldValue::Port(Port::from(1024)),
                                ),
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

        let mut frame = DummyFrame::default_v4();
        frame.dst_port = Some(Port::from(8080));
        assert_eq!(
            eval(tree, &frame),
            Some(Verdict::AllowWarn("high dst port".into()))
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

        let mut frame = DummyFrame::default_v4();
        frame.protocol = Protocol::Udp;
        assert_eq!(eval(tree, &frame), Some(Verdict::Drop));
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

        let mut frame = DummyFrame::default_v4();
        frame.ip_ver = IpVer::V6;
        assert_eq!(eval(tree, &frame), Some(Verdict::Drop));
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
                Pattern::Glob(FieldValue::Ip(IP::new([
                    Octet::Value(192),
                    Octet::Value(168),
                    Octet::Any,
                    Octet::Any,
                ]))),
                ArmEnd::Match(
                    MatchBuilder::with_arm(
                        MatchKind::Hour,
                        Pattern::Range(
                            FieldValue::Hour(Hour::try_from(8).unwrap()),
                            FieldValue::Hour(Hour::try_from(18).unwrap()),
                        ),
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

        // Default: src=192.168.1.10, hour=14 (in [8,18]), day=Wed → Allow
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Allow));
    }

    #[test]
    fn nested_glob_ip_hour_in_range_wrong_day_drops() {
        let tree = RuleTree::new(
            "nested_wrong_day".into(),
            "".into(),
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Glob(FieldValue::Ip(IP::new([
                    Octet::Value(192),
                    Octet::Value(168),
                    Octet::Any,
                    Octet::Any,
                ]))),
                ArmEnd::Match(
                    MatchBuilder::with_arm(
                        MatchKind::Hour,
                        Pattern::Range(
                            FieldValue::Hour(Hour::try_from(8).unwrap()),
                            FieldValue::Hour(Hour::try_from(18).unwrap()),
                        ),
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
        assert_eq!(eval(tree, &DummyFrame::default_v4()), Some(Verdict::Drop));
    }

    #[test]
    fn nested_glob_ip_hour_outside_range_drop_warn() {
        let tree = RuleTree::new(
            "nested_late_hour".into(),
            "".into(),
            MatchBuilder::with_arm(
                MatchKind::SrcIp,
                Pattern::Glob(FieldValue::Ip(IP::new([
                    Octet::Value(192),
                    Octet::Value(168),
                    Octet::Any,
                    Octet::Any,
                ]))),
                ArmEnd::Match(
                    MatchBuilder::with_arm(
                        MatchKind::Hour,
                        Pattern::Range(
                            FieldValue::Hour(Hour::try_from(8).unwrap()),
                            FieldValue::Hour(Hour::try_from(12).unwrap()),
                        ),
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

        // hour=14, not in [8,12] → falls to wildcard → AllowWarn
        assert_eq!(
            eval(tree, &DummyFrame::default_v4()),
            Some(Verdict::DropWarn("hour outside range".into()))
        );
    }
}
