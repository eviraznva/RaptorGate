mod matcher;
mod parsing;

use derive_more::{Debug, Display, Error, PartialEq};

use crate::{frame::{Hour, IP, IpVer, Port, Protocol, Weekday}, rule_tree::matcher::Match};
pub(crate) use matcher::MatchBuilder;

pub(crate) struct RuleTree {
    name: String,
    description: String,
    pub(crate) head: Match
}

impl RuleTree {
    pub fn new(name: String, description: String, head: Match) -> Self {
        Self { name, description, head }
    }

}

#[derive(PartialEq, Debug)]
struct Arm {
    pattern: Pattern,
    into: ArmEnd,
}

#[derive(PartialEq, Debug)]
pub(crate) enum ArmEnd {
    Verdict(Verdict),
    Match(Match),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Verdict {
    Allow,
    Drop,
    AllowWarn(String),
    DropWarn(String),
}

#[derive(Debug, Display, Clone, PartialEq)]
pub(crate) enum Pattern {
    // TODO: move equal into comparision or alternatively remove comparision entirely
    Equal(FieldValue),
    // TODO: remove `Glob`
    Glob(FieldValue),
    #[display("Range - from {}, to {}", _0, _1)]
    Range(FieldValue, FieldValue),
    #[display("Patterns, count: {}", _0.len())]
    Or(Vec<Pattern>),

    #[display("Comparing with {}, to {}", _0, _1)]
    Comparison(Operation, FieldValue),
    Wildcard,
}

#[derive(Debug, Display, Clone, Copy, PartialEq)]
pub(crate) enum FieldValue {
    Ip(IP),
    IpVer(IpVer),
    DayOfWeek(Weekday),
    Hour(Hour),
    Protocol(Protocol),
    Port(Port),
}

#[derive(Debug, Display, Clone, Copy, PartialEq)]
pub(crate) enum MatchKind {
    SrcIp,
    DstIp,
    IpVer,
    DayOfWeek,
    Hour,
    Protocol,
    SrcPort,
    DstPort,
}

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Greater,
    Lesser,
    GreaterOrEqual,
    LesserOrEqual,
}

impl Pattern {
    #[allow(clippy::match_same_arms)]
    fn validate_for(&self, kind: &MatchKind) -> Result<(), RuleError> {
        match (self, kind) {
            (Pattern::Wildcard, _) => Ok(()),

            (Pattern::Equal(_), _) => Ok(()),

            (Pattern::Glob(_), MatchKind::SrcIp | MatchKind::DstIp) => Ok(()),
            (Pattern::Glob(_), _) => Err(RuleError::InvalidPattern(self.clone())),

            (Pattern::Range(..), MatchKind::SrcPort | MatchKind::DstPort | MatchKind::Hour) => Ok(()),
            (Pattern::Range(..), _) => Err(RuleError::InvalidPattern(self.clone())),

            (Pattern::Comparison(..), MatchKind::SrcPort | MatchKind::DstPort | MatchKind::Hour | MatchKind::DayOfWeek) => Ok(()),
            (Pattern::Comparison(..), _) => Err(RuleError::InvalidPattern(self.clone())),

            (Pattern::Or(patterns), MatchKind::Protocol | MatchKind::DayOfWeek | MatchKind::IpVer | MatchKind::Hour | MatchKind::SrcIp | MatchKind::DstIp) => {
                for pattern in patterns {
                    pattern.validate_for(kind)?;
                }
                Ok(())
            }
            (Pattern::Or(_), _) => Err(RuleError::InvalidPattern(self.clone())),
        }
    }
}

pub(crate) enum Step<'a> {
    NeedsMatch { kind: &'a MatchKind, pattern: &'a Pattern },
    Verdict(&'a Verdict),
    NoMatch,
}

pub(crate) struct TreeWalker<'a> {
    current: &'a Match,
    arm_index: usize,
}

impl<'a> TreeWalker<'a> {
    pub fn new(tree: &'a RuleTree) -> Self {
        Self { current: &tree.head, arm_index: 0 }
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
pub(crate) enum RuleError {
    #[display("Invalid Pattern Error, pattern: {}", _0)]
    InvalidPattern(#[error(not(source))] Pattern),
}
#[cfg(test)]
mod tests {
    use crate::frame::Octet;

    use super::*;

    fn dummy_ip() -> IP {
        IP::new([Octet::Value(10), Octet::Value(0), Octet::Value(0), Octet::Value(1)])
    }

    #[test]
    fn glob_invalid_for_non_ip_kinds() {
        let pat = Pattern::Glob(FieldValue::Ip(dummy_ip()));
        let invalid = [
            MatchKind::IpVer,
            MatchKind::DayOfWeek,
            MatchKind::Hour,
            MatchKind::Protocol,
            MatchKind::SrcPort,
            MatchKind::DstPort,
        ];
        for kind in invalid {
            assert!(
                pat.validate_for(&kind).is_err(),
                "Glob should be invalid for {kind}"
            );
        }
    }

    #[test]
    fn range_invalid_for_non_port_non_hour() {
        let pat = Pattern::Range(FieldValue::Port(80.into()), FieldValue::Port(443.into()));
        let invalid = [
            MatchKind::SrcIp,
            MatchKind::DstIp,
            MatchKind::IpVer,
            MatchKind::DayOfWeek,
            MatchKind::Protocol,
        ];
        for kind in invalid {
            assert!(
                pat.validate_for(&kind).is_err(),
                "Range should be invalid for {kind}"
            );
        }
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

