use derive_more::Display;
use thiserror::Error;

use crate::frame::{Hour, IpVer, Port, Protocol, Weekday, IP};
use crate::rule_tree::matcher::Match;
use crate::rule_tree::parsing::ast::{
    AstBody, AstMatch, AstPattern, AstValue, Spanned, Verdict as AstVerdict,
};
use crate::rule_tree::parsing::lexer::Position;
use crate::rule_tree::{
    ArmEnd, FieldValue, MatchBuilder, MatchKind, Operation, Pattern, RuleError, Verdict,
};

#[derive(Debug, Error, Display)]
pub enum LowerError {
    #[display("Unknown match kind '{kind}' at {pos:?}")]
    UnknownKind { kind: String, pos: Position },
    #[display("Unknown value '{value}' for {kind} at {pos:?}")]
    UnknownValue {
        kind: MatchKind,
        value: String,
        pos: Position,
    },
    #[display("Type mismatch for {kind} at {pos:?}")]
    TypeMismatch {
        kind: MatchKind,
        value: AstValue,
        pos: Position,
    },
    #[display("Numeric value out of range for {kind} at {pos:?}")]
    ValueOutOfRange {
        kind: MatchKind,
        value: u64,
        pos: Position,
    },
    #[display("Empty match arms at {pos:?}")]
    EmptyMatch { pos: Position },
    Rule(#[from] RuleError),
}

fn lower_kind(s: &Spanned<String>) -> Result<MatchKind, LowerError> {
    match s.val.as_str() {
        "src_ip" => Ok(MatchKind::SrcIp),
        "dst_ip" => Ok(MatchKind::DstIp),
        "ip_ver" => Ok(MatchKind::IpVer),
        "day_of_week" => Ok(MatchKind::DayOfWeek),
        "hour" => Ok(MatchKind::Hour),
        "protocol" => Ok(MatchKind::Protocol),
        "src_port" => Ok(MatchKind::SrcPort),
        "dst_port" => Ok(MatchKind::DstPort),
        other => Err(LowerError::UnknownKind {
            kind: other.to_string(),
            pos: s.pos,
        }),
    }
}

fn lower_verdict(v: Spanned<AstVerdict>) -> Verdict {
    match v.val {
        AstVerdict::Allow => Verdict::Allow,
        AstVerdict::Drop => Verdict::Drop,
        AstVerdict::AllowWarn(msg) => Verdict::AllowWarn(msg.val),
        AstVerdict::DropWarn(msg) => Verdict::DropWarn(msg.val),
    }
}

fn lower_value(kind: MatchKind, v: Spanned<AstValue>) -> Result<FieldValue, LowerError> {
    let pos = v.pos;

    match v.val {
        AstValue::Ident(s) => match kind {
            MatchKind::IpVer => match s.val.as_str() {
                "v4" => Ok(FieldValue::IpVer(IpVer::V4)),
                "v6" => Ok(FieldValue::IpVer(IpVer::V6)),
                other => Err(LowerError::UnknownValue {
                    kind,
                    value: other.to_string(),
                    pos,
                }),
            },
            MatchKind::Protocol => match s.val.as_str() {
                "tcp" => Ok(FieldValue::Protocol(Protocol::Tcp)),
                "udp" => Ok(FieldValue::Protocol(Protocol::Udp)),
                other => Err(LowerError::UnknownValue {
                    kind,
                    value: other.to_string(),
                    pos,
                }),
            },
            MatchKind::DayOfWeek => match s.val.as_str() {
                "monday" => Ok(FieldValue::DayOfWeek(Weekday::Mon)),
                "tuesday" => Ok(FieldValue::DayOfWeek(Weekday::Tue)),
                "wednesday" => Ok(FieldValue::DayOfWeek(Weekday::Wed)),
                "thursday" => Ok(FieldValue::DayOfWeek(Weekday::Thu)),
                "friday" => Ok(FieldValue::DayOfWeek(Weekday::Fri)),
                "saturday" => Ok(FieldValue::DayOfWeek(Weekday::Sat)),
                "sunday" => Ok(FieldValue::DayOfWeek(Weekday::Sun)),
                other => Err(LowerError::UnknownValue {
                    kind,
                    value: other.to_string(),
                    pos,
                }),
            },
            _ => Err(LowerError::TypeMismatch {
                kind,
                value: AstValue::Ident(s),
                pos,
            }),
        },
        AstValue::StrLit(s) => match kind {
            MatchKind::SrcIp | MatchKind::DstIp => {
                let ip = IP::try_from(s.val.clone()).map_err(|_| LowerError::TypeMismatch {
                    kind,
                    value: AstValue::StrLit(s.clone()),
                    pos,
                })?;
                Ok(FieldValue::Ip(ip))
            }
            _ => Err(LowerError::TypeMismatch {
                kind,
                value: AstValue::StrLit(s),
                pos,
            }),
        },
        AstValue::Number(n) => match kind {
            MatchKind::SrcPort | MatchKind::DstPort => {
                if n.val > u16::MAX as u64 {
                    return Err(LowerError::ValueOutOfRange {
                        kind,
                        value: n.val,
                        pos,
                    });
                }
                Ok(FieldValue::Port(Port::from(n.val as u16)))
            }

            MatchKind::Hour => Ok(FieldValue::Hour(
                    Hour::try_from(u8::try_from(n.val).map_err(|_| LowerError::ValueOutOfRange { kind, value: n.val, pos })?)
                    .map_err(|_| LowerError::ValueOutOfRange { kind, value: n.val, pos })?
            )),

            _ => Err(LowerError::TypeMismatch {
                kind,
                value: AstValue::Number(n),
                pos,
            }),
        },
    }
}

fn lower_pattern(kind: MatchKind, p: Spanned<AstPattern>) -> Result<Pattern, LowerError> {
    match p.val {
        AstPattern::Wildcard => Ok(Pattern::Wildcard),
        AstPattern::Equal(v) => Ok(Pattern::Equal(lower_value(kind, v)?)),
        AstPattern::Greater(v) => Ok(Pattern::Comparison(
                Operation::Greater,
                lower_value(kind, v)?,
        )),
        AstPattern::Lesser(v) => Ok(Pattern::Comparison(
                Operation::Lesser,
                lower_value(kind, v)?,
        )),
        AstPattern::LesserOrEqual(v) => Ok(Pattern::Comparison(
                Operation::LesserOrEqual,
                lower_value(kind, v)?,
        )),
        AstPattern::Or(patterns) => {
            let lowered = patterns
                .val
                .into_iter()
                .map(|inner| {
                    lower_pattern(
                        kind,
                        Spanned {
                            val: inner,
                            pos: patterns.pos,
                        },
                    )
                })
            .collect::<Result<Vec<_>, _>>()?;
            Ok(Pattern::Or(lowered))
        }

        AstPattern::And(patterns) => {
            let lowered = patterns
                .val
                .into_iter()
                .map(|inner| {
                    lower_pattern(
                        kind,
                        Spanned {
                            val: inner,
                            pos: patterns.pos,
                        },
                    )
                })
            .collect::<Result<Vec<_>, _>>()?;
            Ok(Pattern::And(lowered))
        }
        AstPattern::GreaterOrEqual(v) => Ok(Pattern::Comparison(
                Operation::GreaterOrEqual,
                lower_value(kind, v)?,
        )),
    }
}

fn lower_body(body: Spanned<AstBody>) -> Result<ArmEnd, LowerError> {
    match body.val {
        AstBody::Verdict(v) => Ok(ArmEnd::Verdict(lower_verdict(v))),
        AstBody::Match(m) => Ok(ArmEnd::Match(lower(m)?)),
    }
}

pub(super) fn lower(ast: Spanned<AstMatch>) -> Result<Match, LowerError> {
    let kind = lower_kind(ast.val.kind())?;
    let arms_span = ast.val.arms();

    let first = arms_span
        .val
        .first()
        .ok_or(LowerError::EmptyMatch { pos: arms_span.pos })?;

    let mut builder = MatchBuilder::with_arm(
        kind,
        lower_pattern(kind, first.pattern().clone())?,
        lower_body(first.body().clone())?,
    );

    for arm in arms_span.val.iter().skip(1) {
        builder = builder.arm(
            lower_pattern(kind, arm.pattern().clone())?,
            lower_body(arm.body().clone())?,
        );
    }

    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Hour, IpVer, Octet, Port, Protocol, Weekday, IP};
    use crate::rule_tree::parsing::ast::AstArm;
    use crate::rule_tree::{ArmEnd, FieldValue, MatchBuilder, MatchKind, Operation, Pattern, Verdict};
    use crate::rule_tree::parsing::lexer::Position;
 
    // ── AST construction helpers ─────────────────────────────────────────────
    //
    // These build Spanned<T> with a dummy position so test bodies can focus on
    // the value structure, not span bookkeeping.
 
    fn pos() -> Position {
        Position::for_tests(1.into(), 1.into())
    }
 
    fn sp<T>(val: T) -> Spanned<T> {
        Spanned::for_tests(val, pos())
    }
 
    fn arm(pattern: AstPattern, body: AstBody) -> AstArm {
        AstArm::for_tests(sp(pattern), sp(body))
    }
 
    fn verdict_body(v: AstVerdict) -> AstBody {
        AstBody::Verdict(sp(v))
    }
 
    fn match_body(inner: Spanned<AstMatch>) -> AstBody {
        AstBody::Match(inner)
    }
 
    fn ast_match(kind: &str, arms: Vec<AstArm>) -> Spanned<AstMatch> {
        sp(AstMatch::for_tests(sp(kind.to_string()), sp(arms)))
    }
 
    fn equal_ident(s: &str) -> AstPattern {
        AstPattern::Equal(sp(AstValue::Ident(sp(s.to_string()))))
    }
 
    fn equal_num(n: u64) -> AstPattern {
        AstPattern::Equal(sp(AstValue::Number(sp(n))))
    }
 
    fn equal_str(s: &str) -> AstPattern {
        AstPattern::Equal(sp(AstValue::StrLit(sp(s.to_string()))))
    }
 
    fn greater_num(n: u64) -> AstPattern {
        AstPattern::Greater(sp(AstValue::Number(sp(n))))
    }
 
    fn greater_ident(s: &str) -> AstPattern {
        AstPattern::Greater(sp(AstValue::Ident(sp(s.to_string()))))
    }
 
    fn greater_or_equal_num(n: u64) -> AstPattern {
        AstPattern::GreaterOrEqual(sp(AstValue::Number(sp(n))))
    }
 
    fn greater_or_equal_ident(s: &str) -> AstPattern {
        AstPattern::GreaterOrEqual(sp(AstValue::Ident(sp(s.to_string()))))
    }
 
    fn lesser_or_equal_num(n: u64) -> AstPattern {
        AstPattern::LesserOrEqual(sp(AstValue::Number(sp(n))))
    }
 
    fn lesser_or_equal_ident(s: &str) -> AstPattern {
        AstPattern::LesserOrEqual(sp(AstValue::Ident(sp(s.to_string()))))
    }
 
    fn or_patterns(patterns: Vec<AstPattern>) -> AstPattern {
        AstPattern::Or(sp(patterns))
    }
 
    // ── lower_kind ───────────────────────────────────────────────────────────
 
    #[test]
    fn lower_kind_src_ip() {
        assert_eq!(lower_kind(&sp("src_ip".into())).unwrap(), MatchKind::SrcIp);
    }
 
    #[test]
    fn lower_kind_dst_ip() {
        assert_eq!(lower_kind(&sp("dst_ip".into())).unwrap(), MatchKind::DstIp);
    }
 
    #[test]
    fn lower_kind_ip_ver() {
        assert_eq!(lower_kind(&sp("ip_ver".into())).unwrap(), MatchKind::IpVer);
    }
 
    #[test]
    fn lower_kind_day_of_week() {
        assert_eq!(lower_kind(&sp("day_of_week".into())).unwrap(), MatchKind::DayOfWeek);
    }
 
    #[test]
    fn lower_kind_hour() {
        assert_eq!(lower_kind(&sp("hour".into())).unwrap(), MatchKind::Hour);
    }
 
    #[test]
    fn lower_kind_protocol() {
        assert_eq!(lower_kind(&sp("protocol".into())).unwrap(), MatchKind::Protocol);
    }
 
    #[test]
    fn lower_kind_src_port() {
        assert_eq!(lower_kind(&sp("src_port".into())).unwrap(), MatchKind::SrcPort);
    }
 
    #[test]
    fn lower_kind_dst_port() {
        assert_eq!(lower_kind(&sp("dst_port".into())).unwrap(), MatchKind::DstPort);
    }
 
    #[test]
    fn lower_kind_unknown_returns_error() {
        let err = lower_kind(&sp("foobar".into())).unwrap_err();
        assert!(matches!(err, LowerError::UnknownKind { kind, .. } if kind == "foobar"));
    }
 
    // ── lower_verdict ────────────────────────────────────────────────────────
 
    #[test]
    fn lower_verdict_allow() {
        assert_eq!(lower_verdict(sp(AstVerdict::Allow)), Verdict::Allow);
    }
 
    #[test]
    fn lower_verdict_drop() {
        assert_eq!(lower_verdict(sp(AstVerdict::Drop)), Verdict::Drop);
    }
 
    #[test]
    fn lower_verdict_allow_warn() {
        let v = lower_verdict(sp(AstVerdict::AllowWarn(sp("watch out".into()))));
        assert_eq!(v, Verdict::AllowWarn("watch out".into()));
    }
 
    #[test]
    fn lower_verdict_drop_warn() {
        let v = lower_verdict(sp(AstVerdict::DropWarn(sp("blocked".into()))));
        assert_eq!(v, Verdict::DropWarn("blocked".into()));
    }
 
    // ── lower_value ──────────────────────────────────────────────────────────
 
    #[test]
    fn lower_value_ip_ver_v4() {
        let fv = lower_value(MatchKind::IpVer, sp(AstValue::Ident(sp("v4".into())))).unwrap();
        assert_eq!(fv, FieldValue::IpVer(IpVer::V4));
    }
 
    #[test]
    fn lower_value_ip_ver_v6() {
        let fv = lower_value(MatchKind::IpVer, sp(AstValue::Ident(sp("v6".into())))).unwrap();
        assert_eq!(fv, FieldValue::IpVer(IpVer::V6));
    }
 
    #[test]
    fn lower_value_ip_ver_unknown_ident() {
        let err = lower_value(MatchKind::IpVer, sp(AstValue::Ident(sp("v3".into())))).unwrap_err();
        assert!(matches!(err, LowerError::UnknownValue { kind: MatchKind::IpVer, .. }));
    }
 
    #[test]
    fn lower_value_ip_ver_type_mismatch_number() {
        let err = lower_value(MatchKind::IpVer, sp(AstValue::Number(sp(4)))).unwrap_err();
        assert!(matches!(err, LowerError::TypeMismatch { kind: MatchKind::IpVer, .. }));
    }
 
    #[test]
    fn lower_value_protocol_tcp() {
        let fv = lower_value(MatchKind::Protocol, sp(AstValue::Ident(sp("tcp".into())))).unwrap();
        assert_eq!(fv, FieldValue::Protocol(Protocol::Tcp));
    }
 
    #[test]
    fn lower_value_protocol_udp() {
        let fv = lower_value(MatchKind::Protocol, sp(AstValue::Ident(sp("udp".into())))).unwrap();
        assert_eq!(fv, FieldValue::Protocol(Protocol::Udp));
    }
 
    #[test]
    fn lower_value_protocol_unknown_ident() {
        let err = lower_value(MatchKind::Protocol, sp(AstValue::Ident(sp("quic".into())))).unwrap_err();
        assert!(matches!(err, LowerError::UnknownValue { kind: MatchKind::Protocol, .. }));
    }
 
    #[test]
    fn lower_value_day_of_week_all_variants() {
        let days = [
            ("monday",    Weekday::Mon),
            ("tuesday",   Weekday::Tue),
            ("wednesday", Weekday::Wed),
            ("thursday",  Weekday::Thu),
            ("friday",    Weekday::Fri),
            ("saturday",  Weekday::Sat),
            ("sunday",    Weekday::Sun),
        ];
        for (s, expected) in days {
            let fv = lower_value(MatchKind::DayOfWeek, sp(AstValue::Ident(sp(s.into())))).unwrap();
            assert_eq!(fv, FieldValue::DayOfWeek(expected), "failed for {s}");
        }
    }
 
    #[test]
    fn lower_value_day_of_week_unknown_ident() {
        let err = lower_value(MatchKind::DayOfWeek, sp(AstValue::Ident(sp("funday".into())))).unwrap_err();
        assert!(matches!(err, LowerError::UnknownValue { kind: MatchKind::DayOfWeek, .. }));
    }
 
    #[test]
    fn lower_value_src_ip_valid_str() {
        let fv = lower_value(
            MatchKind::SrcIp,
            sp(AstValue::StrLit(sp("192.168.1.10".into()))),
        ).unwrap();
        let expected = IP::new([Octet::Value(192), Octet::Value(168), Octet::Value(1), Octet::Value(10)]);
        assert_eq!(fv, FieldValue::Ip(expected));
    }
 
    #[test]
    fn lower_value_dst_ip_valid_str() {
        let fv = lower_value(
            MatchKind::DstIp,
            sp(AstValue::StrLit(sp("10.0.0.1".into()))),
        ).unwrap();
        let expected = IP::new([Octet::Value(10), Octet::Value(0), Octet::Value(0), Octet::Value(1)]);
        assert_eq!(fv, FieldValue::Ip(expected));
    }
 
    #[test]
    fn lower_value_ip_invalid_str_type_mismatch() {
        let err = lower_value(
            MatchKind::SrcIp,
            sp(AstValue::StrLit(sp("not-an-ip".into()))),
        ).unwrap_err();
        assert!(matches!(err, LowerError::TypeMismatch { kind: MatchKind::SrcIp, .. }));
    }
 
    #[test]
    fn lower_value_str_lit_on_non_ip_kind_type_mismatch() {
        let err = lower_value(
            MatchKind::Protocol,
            sp(AstValue::StrLit(sp("tcp".into()))),
        ).unwrap_err();
        assert!(matches!(err, LowerError::TypeMismatch { kind: MatchKind::Protocol, .. }));
    }
 
    #[test]
    fn lower_value_src_port_number() {
        let fv = lower_value(MatchKind::SrcPort, sp(AstValue::Number(sp(12345)))).unwrap();
        assert_eq!(fv, FieldValue::Port(Port::from(12345)));
    }
 
    #[test]
    fn lower_value_dst_port_number() {
        let fv = lower_value(MatchKind::DstPort, sp(AstValue::Number(sp(80)))).unwrap();
        assert_eq!(fv, FieldValue::Port(Port::from(80)));
    }
 
    #[test]
    fn lower_value_port_out_of_range() {
        let err = lower_value(
            MatchKind::DstPort,
            sp(AstValue::Number(sp(u16::MAX as u64 + 1))),
        ).unwrap_err();
        assert!(matches!(err, LowerError::ValueOutOfRange { kind: MatchKind::DstPort, .. }));
    }
 
    #[test]
    fn lower_value_hour_valid() {
        let fv = lower_value(MatchKind::Hour, sp(AstValue::Number(sp(14)))).unwrap();
        assert_eq!(fv, FieldValue::Hour(Hour::try_from(14).unwrap()));
    }
 
    #[test]
    fn lower_value_hour_out_of_range() {
        // Hour is a u8 with domain validation; 200 should exceed any valid hour
        let err = lower_value(MatchKind::Hour, sp(AstValue::Number(sp(200)))).unwrap_err();
        assert!(matches!(err, LowerError::ValueOutOfRange { kind: MatchKind::Hour, .. }));
    }
 
    #[test]
    fn lower_value_number_on_non_numeric_kind_type_mismatch() {
        let err = lower_value(MatchKind::IpVer, sp(AstValue::Number(sp(4)))).unwrap_err();
        assert!(matches!(err, LowerError::TypeMismatch { kind: MatchKind::IpVer, .. }));
    }
 
    // ── lower_pattern ────────────────────────────────────────────────────────
 
    #[test]
    fn lower_pattern_equal_ip_ver() {
        let p = lower_pattern(MatchKind::IpVer, sp(equal_ident("v4"))).unwrap();
        assert_eq!(p, Pattern::Equal(FieldValue::IpVer(IpVer::V4)));
    }
 
    #[test]
    fn lower_pattern_equal_protocol() {
        let p = lower_pattern(MatchKind::Protocol, sp(equal_ident("tcp"))).unwrap();
        assert_eq!(p, Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)));
    }
 
    #[test]
    fn lower_pattern_equal_src_ip() {
        let p = lower_pattern(
            MatchKind::SrcIp,
            sp(AstPattern::Equal(sp(AstValue::StrLit(sp("192.168.1.10".into()))))),
        ).unwrap();
        let expected = IP::new([Octet::Value(192), Octet::Value(168), Octet::Value(1), Octet::Value(10)]);
        assert_eq!(p, Pattern::Equal(FieldValue::Ip(expected)));
    }
 
    #[test]
    fn lower_pattern_equal_dst_port() {
        let p = lower_pattern(MatchKind::DstPort, sp(equal_num(80))).unwrap();
        assert_eq!(p, Pattern::Equal(FieldValue::Port(Port::from(80))));
    }
 
    #[test]
    fn lower_pattern_equal_hour() {
        let p = lower_pattern(MatchKind::Hour, sp(equal_num(14))).unwrap();
        assert_eq!(p, Pattern::Equal(FieldValue::Hour(Hour::try_from(14).unwrap())));
    }
 
    #[test]
    fn lower_pattern_equal_day_of_week() {
        let p = lower_pattern(MatchKind::DayOfWeek, sp(equal_ident("wednesday"))).unwrap();
        assert_eq!(p, Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)));
    }
 
    #[test]
    fn lower_pattern_greater_dst_port() {
        let p = lower_pattern(MatchKind::DstPort, sp(greater_num(1024))).unwrap();
        assert_eq!(p, Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(1024))));
    }
 
    #[test]
    fn lower_pattern_greater_hour() {
        let p = lower_pattern(MatchKind::Hour, sp(greater_num(10))).unwrap();
        assert_eq!(p, Pattern::Comparison(Operation::Greater, FieldValue::Hour(Hour::try_from(10).unwrap())));
    }
 
    #[test]
    fn lower_pattern_greater_day_of_week() {
        let p = lower_pattern(MatchKind::DayOfWeek, sp(greater_ident("monday"))).unwrap();
        assert_eq!(p, Pattern::Comparison(Operation::Greater, FieldValue::DayOfWeek(Weekday::Mon)));
    }
 
    #[test]
    fn lower_pattern_greater_or_equal_dst_port() {
        let p = lower_pattern(MatchKind::DstPort, sp(greater_or_equal_num(80))).unwrap();
        assert_eq!(p, Pattern::Comparison(Operation::GreaterOrEqual, FieldValue::Port(Port::from(80))));
    }
 
    #[test]
    fn lower_pattern_greater_or_equal_hour() {
        let p = lower_pattern(MatchKind::Hour, sp(greater_or_equal_num(9))).unwrap();
        assert_eq!(p, Pattern::Comparison(Operation::GreaterOrEqual, FieldValue::Hour(Hour::try_from(9).unwrap())));
    }
 
    #[test]
    fn lower_pattern_greater_or_equal_day_of_week() {
        let p = lower_pattern(MatchKind::DayOfWeek, sp(greater_or_equal_ident("monday"))).unwrap();
        assert_eq!(p, Pattern::Comparison(Operation::GreaterOrEqual, FieldValue::DayOfWeek(Weekday::Mon)));
    }
 
    #[test]
    fn lower_pattern_lesser_or_equal_dst_port() {
        let p = lower_pattern(MatchKind::DstPort, sp(lesser_or_equal_num(1024))).unwrap();
        assert_eq!(p, Pattern::Comparison(Operation::LesserOrEqual, FieldValue::Port(Port::from(1024))));
    }
 
    #[test]
    fn lower_pattern_lesser_or_equal_hour() {
        let p = lower_pattern(MatchKind::Hour, sp(lesser_or_equal_num(8))).unwrap();
        assert_eq!(p, Pattern::Comparison(Operation::LesserOrEqual, FieldValue::Hour(Hour::try_from(8).unwrap())));
    }
 
    #[test]
    fn lower_pattern_lesser_or_equal_day_of_week() {
        let p = lower_pattern(MatchKind::DayOfWeek, sp(lesser_or_equal_ident("friday"))).unwrap();
        assert_eq!(p, Pattern::Comparison(Operation::LesserOrEqual, FieldValue::DayOfWeek(Weekday::Fri)));
    }
 
    #[test]
    fn lower_pattern_or_two_protocols() {
        let p = lower_pattern(
            MatchKind::Protocol,
            sp(or_patterns(vec![equal_ident("tcp"), equal_ident("udp")])),
        ).unwrap();
        assert_eq!(p, Pattern::Or(vec![
            Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
            Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
        ]));
    }
 
    #[test]
    fn lower_pattern_or_three_days() {
        let p = lower_pattern(
            MatchKind::DayOfWeek,
            sp(or_patterns(vec![
                equal_ident("monday"),
                equal_ident("wednesday"),
                equal_ident("friday"),
            ])),
        ).unwrap();
        assert_eq!(p, Pattern::Or(vec![
            Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
            Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)),
            Pattern::Equal(FieldValue::DayOfWeek(Weekday::Fri)),
        ]));
    }
 
    #[test]
    fn lower_pattern_or_with_comparison() {
        // | > 1024 | <= 80  →  Or[Comparison(Greater, 1024), Comparison(LesserOrEqual, 80)]
        let p = lower_pattern(
            MatchKind::DstPort,
            sp(or_patterns(vec![greater_num(1024), lesser_or_equal_num(80)])),
        ).unwrap();
        assert_eq!(p, Pattern::Or(vec![
            Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(1024))),
            Pattern::Comparison(Operation::LesserOrEqual, FieldValue::Port(Port::from(80))),
        ]));
    }
 
    #[test]
    fn lower_pattern_or_propagates_inner_error() {
        // One of the Or branches has an unknown ident for Protocol
        let err = lower_pattern(
            MatchKind::Protocol,
            sp(or_patterns(vec![equal_ident("tcp"), equal_ident("quic")])),
        ).unwrap_err();
        assert!(matches!(err, LowerError::UnknownValue { kind: MatchKind::Protocol, .. }));
    }
 
    #[test]
    fn lower_pattern_wildcard() {
        let p = lower_pattern(MatchKind::SrcIp, sp(AstPattern::Wildcard)).unwrap();
        assert_eq!(p, Pattern::Wildcard);
    }
 
    // ── lower_body ───────────────────────────────────────────────────────────
 
    #[test]
    fn lower_body_verdict_allow() {
        let b = lower_body(sp(verdict_body(AstVerdict::Allow))).unwrap();
        assert_eq!(b, ArmEnd::Verdict(Verdict::Allow));
    }
 
    #[test]
    fn lower_body_verdict_drop() {
        let b = lower_body(sp(verdict_body(AstVerdict::Drop))).unwrap();
        assert_eq!(b, ArmEnd::Verdict(Verdict::Drop));
    }
 
    #[test]
    fn lower_body_verdict_allow_warn() {
        let b = lower_body(sp(verdict_body(AstVerdict::AllowWarn(sp("msg".into()))))).unwrap();
        assert_eq!(b, ArmEnd::Verdict(Verdict::AllowWarn("msg".into())));
    }
 
    #[test]
    fn lower_body_verdict_drop_warn() {
        let b = lower_body(sp(verdict_body(AstVerdict::DropWarn(sp("msg".into()))))).unwrap();
        assert_eq!(b, ArmEnd::Verdict(Verdict::DropWarn("msg".into())));
    }
 
    #[test]
    fn lower_body_nested_match() {
        let inner = ast_match("protocol", vec![
            arm(equal_ident("tcp"), verdict_body(AstVerdict::Allow)),
        ]);
        let b = lower_body(sp(match_body(inner))).unwrap();
        let expected = ArmEnd::Match(
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                ArmEnd::Verdict(Verdict::Allow),
            ).build().unwrap(),
        );
        assert_eq!(b, expected);
    }
 
    // ── lower (top-level) ────────────────────────────────────────────────────
    // These mirror the policy_evaluator test cases by building the equivalent
    // AST input rather than parsing a string.
 
    #[test]
    fn lower_single_arm_ip_ver_v4() {
        let ast = ast_match("ip_ver", vec![
            arm(equal_ident("v4"), verdict_body(AstVerdict::Allow)),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::IpVer,
            Pattern::Equal(FieldValue::IpVer(IpVer::V4)),
            ArmEnd::Verdict(Verdict::Allow),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_single_arm_protocol_tcp_drop() {
        let ast = ast_match("protocol", vec![
            arm(equal_ident("tcp"), verdict_body(AstVerdict::Drop)),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::Protocol,
            Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
            ArmEnd::Verdict(Verdict::Drop),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_single_arm_dst_port_allow_warn() {
        let ast = ast_match("dst_port", vec![
            arm(equal_num(80), verdict_body(AstVerdict::AllowWarn(sp("dst port is 80".into())))),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::DstPort,
            Pattern::Equal(FieldValue::Port(Port::from(80))),
            ArmEnd::Verdict(Verdict::AllowWarn("dst port is 80".into())),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_or_protocol_tcp_udp() {
        let ast = ast_match("protocol", vec![
            arm(
                or_patterns(vec![equal_ident("tcp"), equal_ident("udp")]),
                verdict_body(AstVerdict::Allow),
            ),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::Protocol,
            Pattern::Or(vec![
                Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
            ]),
            ArmEnd::Verdict(Verdict::Allow),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_or_three_days() {
        let ast = ast_match("day_of_week", vec![
            arm(
                or_patterns(vec![
                    equal_ident("monday"),
                    equal_ident("wednesday"),
                    equal_ident("friday"),
                ]),
                verdict_body(AstVerdict::Allow),
            ),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::DayOfWeek,
            Pattern::Or(vec![
                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Wed)),
                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Fri)),
            ]),
            ArmEnd::Verdict(Verdict::Allow),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_multiple_arms_protocol() {
        let ast = ast_match("protocol", vec![
            arm(equal_ident("tcp"), verdict_body(AstVerdict::Allow)),
            arm(equal_ident("udp"), verdict_body(AstVerdict::Drop)),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::Protocol,
            Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
            ArmEnd::Verdict(Verdict::Allow),
        ).arm(
            Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
            ArmEnd::Verdict(Verdict::Drop),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_comparison_dst_port_greater() {
        let ast = ast_match("dst_port", vec![
            arm(greater_num(79), verdict_body(AstVerdict::Allow)),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::DstPort,
            Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(79))),
            ArmEnd::Verdict(Verdict::Allow),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_comparison_dst_port_greater_or_equal() {
        let ast = ast_match("dst_port", vec![
            arm(greater_or_equal_num(80), verdict_body(AstVerdict::Allow)),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::DstPort,
            Pattern::Comparison(Operation::GreaterOrEqual, FieldValue::Port(Port::from(80))),
            ArmEnd::Verdict(Verdict::Allow),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_comparison_dst_port_lesser_or_equal() {
        let ast = ast_match("dst_port", vec![
            arm(lesser_or_equal_num(80), verdict_body(AstVerdict::Allow)),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::DstPort,
            Pattern::Comparison(Operation::LesserOrEqual, FieldValue::Port(Port::from(80))),
            ArmEnd::Verdict(Verdict::Allow),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_comparison_hour_greater_or_equal() {
        let ast = ast_match("hour", vec![
            arm(greater_or_equal_num(9), verdict_body(AstVerdict::Allow)),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::Hour,
            Pattern::Comparison(Operation::GreaterOrEqual, FieldValue::Hour(Hour::try_from(9).unwrap())),
            ArmEnd::Verdict(Verdict::Allow),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_comparison_day_of_week_greater_or_equal() {
        let ast = ast_match("day_of_week", vec![
            arm(greater_or_equal_ident("monday"), verdict_body(AstVerdict::Allow)),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::DayOfWeek,
            Pattern::Comparison(Operation::GreaterOrEqual, FieldValue::DayOfWeek(Weekday::Mon)),
            ArmEnd::Verdict(Verdict::Allow),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_nested_ipver_protocol_dst_port() {
        let ast = ast_match("ip_ver", vec![
            arm(
                equal_ident("v4"),
                match_body(ast_match("protocol", vec![
                    arm(
                        equal_ident("tcp"),
                        match_body(ast_match("dst_port", vec![
                            arm(lesser_or_equal_num(1024), verdict_body(AstVerdict::Allow)),
                            arm(greater_num(1024),         verdict_body(AstVerdict::AllowWarn(sp("high dst port".into())))),
                        ])),
                    ),
                    arm(equal_ident("udp"), verdict_body(AstVerdict::Drop)),
                ])),
            ),
            arm(equal_ident("v6"), verdict_body(AstVerdict::Drop)),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
            MatchKind::IpVer,
            Pattern::Equal(FieldValue::IpVer(IpVer::V4)),
            ArmEnd::Match(
                MatchBuilder::with_arm(
                    MatchKind::Protocol,
                    Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
                    ArmEnd::Match(
                        MatchBuilder::with_arm(
                            MatchKind::DstPort,
                            Pattern::Comparison(Operation::LesserOrEqual, FieldValue::Port(Port::from(1024))),
                            ArmEnd::Verdict(Verdict::Allow),
                        ).arm(
                            Pattern::Comparison(Operation::Greater, FieldValue::Port(Port::from(1024))),
                            ArmEnd::Verdict(Verdict::AllowWarn("high dst port".into())),
                        ).build().unwrap(),
                    ),
                ).arm(
                    Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
                    ArmEnd::Verdict(Verdict::Drop),
                ).build().unwrap(),
            ),
        ).arm(
            Pattern::Equal(FieldValue::IpVer(IpVer::V6)),
            ArmEnd::Verdict(Verdict::Drop),
        ).build().unwrap());
    }
 
    #[test]
    fn lower_nested_or_at_outer_and_inner_levels() {
        let ast = ast_match("ip_ver", vec![
            arm(
                or_patterns(vec![equal_ident("v4"), equal_ident("v6")]),
                match_body(ast_match("protocol", vec![
                    arm(
                        or_patterns(vec![equal_ident("tcp"), equal_ident("udp")]),
                        verdict_body(AstVerdict::Allow),
                    ),
                ])),
            ),
        ]);
        let result = lower(ast).unwrap();
        assert_eq!(result, MatchBuilder::with_arm(
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
                ).build().unwrap(),
            ),
        ).build().unwrap());
    }
 
    // ── lower error cases ────────────────────────────────────────────────────
 
    #[test]
    fn lower_empty_arms_returns_error() {
        let ast = ast_match("protocol", vec![]); // no arms
        let err = lower(ast).unwrap_err();
        assert!(matches!(err, LowerError::EmptyMatch { .. }));
    }
 
    #[test]
    fn lower_unknown_kind_returns_error() {
        let ast = ast_match("banana", vec![
            arm(equal_ident("tcp"), verdict_body(AstVerdict::Allow)),
        ]);
        let err = lower(ast).unwrap_err();
        assert!(matches!(err, LowerError::UnknownKind { kind, .. } if kind == "banana"));
    }
 
    #[test]
    fn lower_bad_value_in_arm_propagates_error() {
        let ast = ast_match("ip_ver", vec![
            arm(equal_ident("v5"), verdict_body(AstVerdict::Allow)),
        ]);
        let err = lower(ast).unwrap_err();
        assert!(matches!(err, LowerError::UnknownValue { kind: MatchKind::IpVer, .. }));
    }
}
