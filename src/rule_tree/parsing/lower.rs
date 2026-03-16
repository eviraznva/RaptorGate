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
        AstPattern::Glob => Ok(Pattern::Wildcard),
        AstPattern::Equal(v) => Ok(Pattern::Equal(lower_value(kind, v)?)),
        AstPattern::Greater(v) => Ok(Pattern::Comparison(
                Operation::Greater,
                lower_value(kind, v)?,
        )),
        AstPattern::LesserOrEqual(v) => Ok(Pattern::Comparison(
                Operation::LesserOrEqual,
                lower_value(kind, v)?,
        )),
        AstPattern::Range(from, to) => Ok(Pattern::Range(
                lower_value(kind, from)?,
                lower_value(kind, to)?,
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
