pub mod matcher;
pub mod parsing;
pub mod types;

use std::fmt::Display;

use serde::{Deserialize, Serialize};
pub use types::{ArrivalInfo, Hour, IPError, IpGlobbable, IpVer, Octet, Port, Protocol, Weekday};
use serde::ser::SerializeStruct;

use derive_more::{Debug, Display, Error, PartialEq};

use crate::{policy::parse_rule_tree, rule_tree::matcher::Match};
pub use matcher::MatchBuilder;

#[derive(Clone, Debug, Display)]
pub struct RuleTree {
    pub head: Match,
}

impl Serialize for RuleTree {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut state = s.serialize_struct("RuleTree", 1)?;
        state.serialize_field("head", &self.head.to_string())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RuleTree {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            name: String,
            description: String,
            head: String,
        }

        let raw = Raw::deserialize(d)?;
        let tree = parse_rule_tree(&raw.head).map_err(serde::de::Error::custom)?;

        Ok(RuleTree { head: tree })
    }
}

impl RuleTree {
    pub fn new(head: Match) -> Self {
        Self {
            head,
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
struct Arm {
    pattern: Pattern,
    into: ArmEnd,
}

impl Arm {
    fn fmt_indented(&self, f: &mut std::fmt::Formatter<'_>, indent: usize) -> std::fmt::Result {
        let indent_str = "\t".repeat(indent);
        match &self.into {
            ArmEnd::Verdict(v) => writeln!(f, "{}{}: {}", indent_str, self.pattern, v),
            ArmEnd::Match(m) => {
                writeln!(f, "{}{}: ", indent_str, self.pattern)?;
                m.fmt_indented(f, indent + 1)
            }
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum ArmEnd {
    Verdict(Verdict),
    Match(Match),
}

#[derive(Debug, Clone, PartialEq, Display)]
pub enum Verdict {
    #[display("verdict allow")]
    Allow,
    #[display("verdict drop")]
    Drop,
    #[display("verdict allow_warn \"{}\"", _0)]
    AllowWarn(String),
    #[display("verdict drop_warn \"{}\"", _0)]
    DropWarn(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    // TODO: move equal into comparision or alternatively remove comparision entirely
    Equal(FieldValue),
    Or(Vec<Pattern>),
    And(Vec<Pattern>),

    Comparison(Operation, FieldValue),
    Wildcard,
}

impl Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pattern::Equal(val) => write!(f, "= {val}"),
            Pattern::Comparison(op, val) => write!(f, "{op} {val}"),
            Pattern::Or(patterns) => {
                let patterns_str = format!("|({})", 
                    patterns
                        .iter()
                        .map(|p| format!("{p}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                );

                write!(f, "{patterns_str}")
            }
            Pattern::And(patterns) => {
                let patterns_str = format!("&({})", 
                    patterns
                        .iter()
                        .map(|p| format!("{p}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                );

                write!(f, "{patterns_str}")
            }
            Pattern::Wildcard => write!(f, "_"),
        }
    }
}

#[derive(Debug, Display, Clone, Copy, PartialEq)]
pub enum FieldValue {
    Ip(IpGlobbable),
    IpVer(IpVer),
    DayOfWeek(Weekday),
    Hour(Hour),
    Protocol(Protocol),
    Port(Port),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MatchKind {
    SrcIp,
    DstIp,
    IpVer,
    DayOfWeek,
    Hour,
    Protocol,
    SrcPort,
    DstPort,
}

impl std::fmt::Display for MatchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MatchKind::SrcIp    => "src_ip",
            MatchKind::DstIp    => "dst_ip",
            MatchKind::IpVer    => "ip_ver",
            MatchKind::DayOfWeek => "day_of_week",
            MatchKind::Hour     => "hour",
            MatchKind::Protocol => "protocol",
            MatchKind::SrcPort  => "src_port",
            MatchKind::DstPort  => "dst_port",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    #[display(">")]
    Greater,
    #[display("<")]
    Lesser,
    #[display(">=")]
    GreaterOrEqual,
    #[display("<=")]
    LesserOrEqual,
}

impl Pattern {
    #[allow(clippy::match_same_arms)]
    fn validate_for(&self, kind: &MatchKind) -> Result<(), RuleError> {
        match (self, kind) {
            (Pattern::Wildcard, _) => Ok(()),

            (Pattern::Equal(_), _) => Ok(()),
            (
                Pattern::Comparison(..),
                MatchKind::SrcPort | MatchKind::DstPort | MatchKind::Hour | MatchKind::DayOfWeek,
            ) => Ok(()),
            (Pattern::Comparison(..), _) => Err(RuleError::InvalidPattern(self.clone())),

            (Pattern::Or(patterns) | Pattern::And(patterns), _) => {
                for pattern in patterns {
                    pattern.validate_for(kind)?;
                }
                Ok(())
            } // (Pattern::Or(_), _) => Err(RuleError::InvalidPattern(self.clone())),
        }
    }
}

pub enum Step<'a> {
    NeedsMatch {
        kind: &'a MatchKind,
        pattern: &'a Pattern,
    },
    Verdict(&'a Verdict),
    NoMatch,
}

pub struct TreeWalker<'a> {
    current: &'a Match,
    arm_index: usize,
}

impl<'a> TreeWalker<'a> {
    pub fn new(tree: &'a RuleTree) -> Self {
        Self {
            current: &tree.head,
            arm_index: 0,
        }
    }

    pub fn current_step(&self) -> Step<'a> {
        match self.current.arms().get(self.arm_index) {
            Some(arm) => Step::NeedsMatch {
                kind: self.current.kind(),
                pattern: &arm.pattern,
            },
            None => Step::NoMatch,
        }
    }

    pub fn advance(&mut self, matched: bool) -> Step<'a> {
        let arm = &self.current.arms()[self.arm_index];

        if matched {
            match &arm.into {
                ArmEnd::Verdict(v) => Step::Verdict(v),
                ArmEnd::Match(next) => {
                    self.current = next;
                    self.arm_index = 0;
                    self.current_step()
                }
            }
        } else {
            self.arm_index += 1;
            self.current_step()
        }
    }
}

#[derive(Debug, Display, Error)]
pub enum RuleError {
    #[display("Invalid Pattern Error, pattern: {}", _0)]
    InvalidPattern(#[error(not(source))] Pattern),
}
#[cfg(test)]
mod tests {

    use super::*;

    fn dummy_ip() -> IpGlobbable {
        IpGlobbable::new([
            Octet::Value(10),
            Octet::Value(0),
            Octet::Value(0),
            Octet::Value(1),
        ])
    }

    #[test]
    fn comparison_invalid_for_ip_protocol_ipver() {
        let pat = Pattern::Comparison(Operation::Lesser, FieldValue::Port(80.into()));
        let invalid = [
            MatchKind::SrcIp,
            MatchKind::DstIp,
            MatchKind::IpVer,
            MatchKind::Protocol,
        ];
        for kind in invalid {
            assert!(
                pat.validate_for(&kind).is_err(),
                "Comparison should be invalid for {kind}"
            );
        }
    }

    // #[test]
    // fn or_invalid_for_port_kinds() {
    //     let pat = Pattern::Or(vec![Pattern::Equal(FieldValue::Port(80.into()))]);
    //     let invalid = [MatchKind::SrcPort, MatchKind::DstPort];
    //     for kind in invalid {
    //         assert!(
    //             pat.validate_for(&kind).is_err(),
    //             "Or should be invalid for {kind}"
    //         );
    //     }
    // }

    #[test]
    fn or_accepts_all_valid_nested_patterns_for_kind() {
        let pat = Pattern::Or(vec![
            Pattern::Equal(FieldValue::Protocol(Protocol::Tcp)),
            Pattern::Equal(FieldValue::Protocol(Protocol::Udp)),
        ]);

        assert!(
            pat.validate_for(&MatchKind::Protocol).is_ok(),
            "Or should accept valid nested patterns for Protocol"
        );
    }
}
