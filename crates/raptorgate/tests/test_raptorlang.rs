// ── Equal: IpVer ──────────────────────────────────────────
// Mirrors: equal_ip_ver_match / equal_ip_ver_no_match

use ngfw::rule_tree::{
    matcher::{Match, MatchBuilder},
    parsing::parse_rule_tree,
    ArmEnd, ArrivalInfo, FieldValue, Hour, IpGlobbable as IP, IpVer, MatchKind, Octet, Operation,
    Pattern, Port, Protocol, Verdict, Weekday,
};

fn assert_lower_eq(source: &str, expected: Match) {
    let actual = parse_rule_tree(source).unwrap();
    assert_eq!(actual, expected);
}

macro_rules! test_parse_and_stringify {
    ($fn_name:ident, $input_string:expr, $output_tree:expr) => {
        #[test]
        fn $fn_name() {
            assert_lower_eq($input_string, $output_tree.build().unwrap());
        }

        paste::paste! {
            #[test]
            fn [< $fn_name _stringify >]() {
                // assert_lower_eq($input_string, $output_tree.build().unwrap());
                let tree = parse_rule_tree($input_string).unwrap();
                let stringified = tree.to_string();
                let tree_from_stringified = parse_rule_tree(&stringified).unwrap();

                assert_eq!(tree, tree_from_stringified);
            }
        }
    }
}

test_parse_and_stringify!(
    lower_equal_ip_ver_v4,
    "match ip_ver { = v4 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::IpVer,
        Pattern::Equal(FieldValue::IpVer(IpVer::V4)),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

test_parse_and_stringify!(
    lower_equal_ip_ver_v6,
    "match ip_ver { = v6 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::IpVer,
        Pattern::Equal(FieldValue::IpVer(IpVer::V6)),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// ── Equal: Protocol ───────────────────────────────────────
// Mirrors: equal_protocol_match / equal_protocol_no_match

test_parse_and_stringify!(
    lower_equal_protocol_tcp,
    "match protocol { = tcp : verdict drop }",
    MatchBuilder::with_arm(
        MatchKind::Protocol,
        Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
        ArmEnd::Verdict(Verdict::Drop),
    )
);

test_parse_and_stringify!(
    lower_equal_protocol_udp,
    "match protocol { = udp : verdict drop }",
    MatchBuilder::with_arm(
        MatchKind::Protocol,
        Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
        ArmEnd::Verdict(Verdict::Drop),
    )
);

// ── Equal: Src IP ─────────────────────────────────────────
// Mirrors: equal_src_ip_match / equal_src_ip_no_match

test_parse_and_stringify!(
    lower_equal_src_ip_match,
    r#"match src_ip { = "192.168.1.10" : verdict allow }"#,
    MatchBuilder::with_arm(
        MatchKind::SrcIp,
        Pattern::Equal(FieldValue::Ip(IP::new([
            Octet::Value(192),
            Octet::Value(168),
            Octet::Value(1),
            Octet::Value(10),
        ]))),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

test_parse_and_stringify!(
    lower_equal_src_ip_no_match,
    r#"match src_ip { = "10.10.10.10" : verdict allow }"#,
    MatchBuilder::with_arm(
        MatchKind::SrcIp,
        Pattern::Equal(FieldValue::Ip(IP::new([
            Octet::Value(10),
            Octet::Value(10),
            Octet::Value(10),
            Octet::Value(10),
        ]))),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// ── Equal: Dst IP ─────────────────────────────────────────
// Mirrors: equal_dst_ip_match

test_parse_and_stringify!(
    lower_equal_dst_ip,
    r#"match dst_ip { = "10.0.0.1" : verdict allow }"#,
    MatchBuilder::with_arm(
        MatchKind::DstIp,
        Pattern::Equal(FieldValue::Ip(IP::new([
            Octet::Value(10),
            Octet::Value(0),
            Octet::Value(0),
            Octet::Value(1),
        ]))),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// ── Equal: Src Port ───────────────────────────────────────
// Mirrors: equal_src_port_match / equal_src_port_no_match

test_parse_and_stringify!(
    lower_equal_src_port_match,
    "match src_port { = 12345 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::SrcPort,
        Pattern::Equal(FieldValue::Port(Port::from(12345))),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

test_parse_and_stringify!(
    lower_equal_src_port_no_match,
    "match src_port { = 9999 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::SrcPort,
        Pattern::Equal(FieldValue::Port(Port::from(9999))),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// ── Equal: Dst Port ───────────────────────────────────────
// Mirrors: equal_dst_port_match (AllowWarn verdict)

test_parse_and_stringify!(
    lower_equal_dst_port_allow_warn,
    r#"match dst_port { = 80 : verdict allow_warn "dst port is 80" }"#,
    MatchBuilder::with_arm(
        MatchKind::DstPort,
        Pattern::Equal(FieldValue::Port(Port::from(80))),
        ArmEnd::Verdict(Verdict::AllowWarn("dst port is 80".into())),
    )
);

// ── Equal: Hour ───────────────────────────────────────────
// Mirrors: equal_hour_match / equal_hour_no_match

test_parse_and_stringify!(
    lower_equal_hour_match,
    "match hour { = 14 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::Hour,
        Pattern::Equal(FieldValue::Hour(Hour::try_from(14).unwrap())),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

test_parse_and_stringify!(
    lower_equal_hour_no_match,
    "match hour { = 3 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::Hour,
        Pattern::Equal(FieldValue::Hour(Hour::try_from(3).unwrap())),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// ── Equal: DayOfWeek ──────────────────────────────────────
// Mirrors: equal_day_of_week_match / equal_day_of_week_no_match

test_parse_and_stringify!(
    lower_equal_day_of_week_wednesday,
    "match day_of_week { = wednesday : verdict drop }",
    MatchBuilder::with_arm(
        MatchKind::DayOfWeek,
        Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)),
        ArmEnd::Verdict(Verdict::Drop),
    )
);

test_parse_and_stringify!(
    lower_equal_day_of_week_monday,
    "match day_of_week { = monday : verdict drop }",
    MatchBuilder::with_arm(
        MatchKind::DayOfWeek,
        Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
        ArmEnd::Verdict(Verdict::Drop),
    )
);

// ── Comparison: Dst Port ──────────────────────────────────
// Mirrors: comparison_dst_port_greater / comparison_dst_port_greater_fail
//          comparison_dst_port_lesser_or_equal
// Note: Operation::Lesser and Operation::GreaterOrEqual have no AST source
//       (AstPattern only has Greater and LesserOrEqual), so those evaluator
//       tests have no lower counterpart.

test_parse_and_stringify!(
    lower_comparison_dst_port_greater,
    "match dst_port { > 79 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::DstPort,
        Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(79))),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

test_parse_and_stringify!(
    lower_comparison_dst_port_greater_at_boundary,
    "match dst_port { > 80 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::DstPort,
        Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(80))),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

test_parse_and_stringify!(
    lower_comparison_dst_port_lesser_or_equal,
    "match dst_port { <= 80 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::DstPort,
        Pattern::Comparison(Operation::LesserOrEqual, FieldValue::Port(Port::from(80))),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// ── Comparison: Hour ──────────────────────────────────────
// Mirrors: comparison_hour_greater / comparison_hour_lesser_fail

test_parse_and_stringify!(
    lower_comparison_hour_greater,
    "match hour { > 10 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::Hour,
        Pattern::Comparison(
            Operation::Greater,
            FieldValue::Hour(Hour::try_from(10).unwrap()),
        ),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

test_parse_and_stringify!(
    lower_comparison_hour_lesser_or_equal,
    "match hour { <= 9 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::Hour,
        Pattern::Comparison(
            Operation::LesserOrEqual,
            FieldValue::Hour(Hour::try_from(9).unwrap()),
        ),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// ── Comparison: DayOfWeek ─────────────────────────────────
// Mirrors: comparison_day_of_week_greater_or_equal /
//          comparison_day_of_week_lesser / comparison_day_of_week_lesser_fail

test_parse_and_stringify!(
    lower_comparison_day_of_week_greater,
    // Greater is the closest AST-producible equivalent to GreaterOrEqual
    "match day_of_week { > monday : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::DayOfWeek,
        Pattern::Comparison(Operation::Greater, FieldValue::DayOfWeek(Weekday::Mon)),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

test_parse_and_stringify!(
    lower_comparison_day_of_week_lesser_or_equal,
    "match day_of_week { <= friday : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::DayOfWeek,
        Pattern::Comparison(
            Operation::LesserOrEqual,
            FieldValue::DayOfWeek(Weekday::Fri),
        ),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// ── Or ────────────────────────────────────────────────────
// Mirrors: or_protocol_matches_first / or_protocol_matches_second /
//          or_protocol_no_match

test_parse_and_stringify!(
    lower_or_protocol_tcp_udp,
    "match protocol { |(= tcp = udp) : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::Protocol,
        Pattern::Or(vec![
            Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
            Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
        ]),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// Mirrors: or_day_of_week (three-value Or)
test_parse_and_stringify!(
    lower_or_day_of_week_three_values,
    "match day_of_week { |( = monday = wednesday = friday) : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::DayOfWeek,
        Pattern::Or(vec![
            Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
            Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)),
            Pattern::Equal(FieldValue::DayOfWeek(Weekday::Fri)),
        ]),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// ── Multiple arms ────────────────────────────────────────
// Mirrors: multiple_arms_first_matches / multiple_arms_second_matches /
//          multiple_arms_none_match

test_parse_and_stringify!(
    lower_multiple_arms_protocol_tcp_then_udp,
    "match protocol { = tcp : verdict allow  = udp : verdict drop }",
    MatchBuilder::with_arm(
        MatchKind::Protocol,
        Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
        ArmEnd::Verdict(Verdict::Allow),
    )
    .arm(
        Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
        ArmEnd::Verdict(Verdict::Drop),
    )
);

test_parse_and_stringify!(
    lower_multiple_arms_neither_tcp_nor_udp,
    // tree where frame protocol (tcp by default) matches neither arm
    "match protocol { = udp : verdict allow  = udp : verdict drop }",
    MatchBuilder::with_arm(
        MatchKind::Protocol,
        Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
        ArmEnd::Verdict(Verdict::Allow),
    )
    .arm(
        Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
        ArmEnd::Verdict(Verdict::Drop),
    )
);

// ── Port extraction (portless protocol) ──────────────────
// Mirrors: icmp_frame_port_extraction_returns_none

test_parse_and_stringify!(
    lower_src_port_equal_for_portless_frame,
    "match src_port { = 80 : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::SrcPort,
        Pattern::Equal(FieldValue::Port(Port::from(80))),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

// ── DropWarn verdict ─────────────────────────────────────
// Mirrors: nested_glob_ip_hour_outside_range_drop_warn

test_parse_and_stringify!(
    lower_drop_warn_verdict,
    r#"match hour { > 12 : verdict allow  <= 12 : verdict drop_warn "hour outside range" }"#,
    MatchBuilder::with_arm(
        MatchKind::Hour,
        Pattern::Comparison(
            Operation::Greater,
            FieldValue::Hour(Hour::try_from(12).unwrap()),
        ),
        ArmEnd::Verdict(Verdict::Allow),
    )
    .arm(
        Pattern::Comparison(
            Operation::LesserOrEqual,
            FieldValue::Hour(Hour::try_from(12).unwrap()),
        ),
        ArmEnd::Verdict(Verdict::DropWarn("hour outside range".into())),
    )
);

// ── Nested: IpVer → Protocol → DstPort ───────────────────
// Mirrors: nested_ipver_then_protocol_then_dst_port_allow
//          nested_v4_tcp_high_port_allow_warn
// (Range is replaced with comparison equivalents because AstPattern has no
//  Range parser path in the base grammar; > and <= cover the same cases.)

test_parse_and_stringify!(
    lower_nested_ipver_protocol_dst_port,
    "match ip_ver { \
        = v4 : match protocol { \
            = tcp : match dst_port { \
                <= 1024 : verdict allow \
                    > 1024 : verdict allow_warn \"high dst port\" \
            } \
            = udp : verdict drop \
        } \
        = v6 : verdict drop \
        }",
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
                        Pattern::Comparison(
                            Operation::LesserOrEqual,
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
);

// Mirrors: nested_v4_udp_drop
test_parse_and_stringify!(
    lower_nested_v4_udp_drop,
    "match ip_ver { \
        = v4 : match protocol { \
            = tcp : verdict allow \
                = udp : verdict drop \
        } \
        }",
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
);

// Mirrors: nested_v6_drop
test_parse_and_stringify!(
    lower_nested_v6_drop,
    "match ip_ver { \
        = v4 : verdict allow \
        = v6 : verdict drop \
        }",
    MatchBuilder::with_arm(
        MatchKind::IpVer,
        Pattern::Equal(FieldValue::IpVer(IpVer::V4)),
        ArmEnd::Verdict(Verdict::Allow),
    )
    .arm(
        Pattern::Equal(FieldValue::IpVer(IpVer::V6)),
        ArmEnd::Verdict(Verdict::Drop),
    )
);

test_parse_and_stringify!(
    lower_day_of_week_wildcard,
    "match day_of_week { = monday : verdict allow  _ : verdict drop }",
    MatchBuilder::with_arm(
        MatchKind::DayOfWeek,
        Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
        ArmEnd::Verdict(Verdict::Allow),
    )
    .arm(Pattern::Wildcard, ArmEnd::Verdict(Verdict::Drop))
);

// ── Nested: hour comparison → day_of_week ────────────────
// Mirrors: nested_glob_ip_then_hour_range_then_day family

test_parse_and_stringify!(
    lower_nested_hour_then_day_of_week_allow,
    // hour > 8  →  day_of_week = wednesday → Allow; = monday → Drop
    // hour <= 8 →  AllowWarn
    "match hour { \
        > 8 : match day_of_week { \
            = wednesday : verdict allow \
                = monday : verdict drop \
        } \
        <= 8 : verdict allow_warn \"hour outside range\" \
        }",
    MatchBuilder::with_arm(
        MatchKind::Hour,
        Pattern::Comparison(
            Operation::Greater,
            FieldValue::Hour(Hour::try_from(8).unwrap()),
        ),
        ArmEnd::Match(
            MatchBuilder::with_arm(
                MatchKind::DayOfWeek,
                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .arm(
                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        ),
    )
    .arm(
        Pattern::Comparison(
            Operation::LesserOrEqual,
            FieldValue::Hour(Hour::try_from(8).unwrap()),
        ),
        ArmEnd::Verdict(Verdict::AllowWarn("hour outside range".into())),
    )
);

test_parse_and_stringify!(
    lower_nested_hour_wrong_day_drops,
    // Same structure as above but only Monday is allowed, so Wednesday falls
    // through to the wildcard Drop arm (tested via tree shape, not evaluation).
    "match hour { \
        > 8 : match day_of_week { \
            = monday : verdict allow \
                = wednesday : verdict drop \
        } \
        }",
    MatchBuilder::with_arm(
        MatchKind::Hour,
        Pattern::Comparison(
            Operation::Greater,
            FieldValue::Hour(Hour::try_from(8).unwrap()),
        ),
        ArmEnd::Match(
            MatchBuilder::with_arm(
                MatchKind::DayOfWeek,
                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .arm(
                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .build()
            .unwrap(),
        ),
    )
);

// AND
test_parse_and_stringify!(
    src_port_and,
    "match src_port { &( > 80 < 90 ) : verdict allow }",
    MatchBuilder::with_arm(
        MatchKind::SrcPort,
        Pattern::And(vec![
            Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(80))),
            Pattern::Comparison(Operation::Lesser, FieldValue::Port(Port::from(90))),
        ]),
        ArmEnd::Verdict(Verdict::Allow),
    )
);

test_parse_and_stringify!(
    src_port_and_or,
    "match src_port { |(&( > 80 < 90 ) =100) : verdict allow }",
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
);

// ── Nested ORs ───────────────────────────────────────────
// User-requested: an Or pattern as input to a nested match, plus an Or
// pattern inside the nested match, exercising Or lowering at multiple levels.

test_parse_and_stringify!(
    lower_nested_or_at_outer_and_inner_levels,
    // (ip_ver = v4 | ip_ver = v6) →
    //   (protocol = tcp | protocol = udp) → Allow
    "match ip_ver { \
        |( = v4 =v6) : match protocol { \
            |( = tcp =udp) : verdict allow \
        } \
        }",
    MatchBuilder::with_arm(
        MatchKind::IpVer,
        Pattern::Or(vec![
            Pattern::Equal(FieldValue::IpVer(IpVer::V4)),
            Pattern::Equal(FieldValue::IpVer(IpVer::V6)),
        ]),
        ArmEnd::Match(
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
        ),
    )
);

test_parse_and_stringify!(
    lower_nested_or_three_days_then_port_comparison,
    // (day = Mon | Wed | Fri) →
    //   dst_port > 1024 → DropWarn; <= 1024 → Allow
    "match day_of_week { \
        |( = monday = wednesday = friday ) : match dst_port { \
            > 1024 : verdict drop_warn \"high port on work day\" \
                <= 1024 : verdict allow \
        } \
        }",
    MatchBuilder::with_arm(
        MatchKind::DayOfWeek,
        Pattern::Or(vec![
            Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
            Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)),
            Pattern::Equal(FieldValue::DayOfWeek(Weekday::Fri)),
        ]),
        ArmEnd::Match(
            MatchBuilder::with_arm(
                MatchKind::DstPort,
                Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(1024))),
                ArmEnd::Verdict(Verdict::DropWarn("high port on work day".into())),
            )
            .arm(
                Pattern::Comparison(
                    Operation::LesserOrEqual,
                    FieldValue::Port(Port::from(1024)),
                ),
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .unwrap(),
        ),
    )
);
