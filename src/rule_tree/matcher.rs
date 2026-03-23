use derive_more::Debug;
use nonempty::NonEmpty;

use crate::{
    frame::{Hour, Octet, Weekday},
    rule_tree::{
        Arm, ArmEnd, FieldValue, IpVer, MatchKind, Operation, Pattern, RuleError, RuleTree, Verdict,
    },
};

#[derive(PartialEq, Debug)]
pub struct Match {
    kind: MatchKind,
    arms: NonEmpty<Box<Arm>>,
}

impl Match {
    fn new(kind: MatchKind, arms: NonEmpty<Box<Arm>>) -> Result<Self, RuleError> {
        for arm in &arms {
            arm.pattern.validate_for(&kind)?;
        }

        Ok(Self { kind, arms })
    }

    pub(super) fn kind(&self) -> &MatchKind {
        &self.kind
    }

    pub(super) fn arms(&self) -> &NonEmpty<Box<Arm>> {
        &self.arms
    }
}

pub struct MatchBuilder {
    kind: MatchKind,
    arms: NonEmpty<Box<Arm>>,
}

impl MatchBuilder {
    pub fn with_arm(kind: MatchKind, pattern: Pattern, into: ArmEnd) -> Self {
        Self {
            kind,
            arms: NonEmpty::new(Box::new(Arm { pattern, into })),
        }
    }

    pub fn arm(mut self, pattern: Pattern, into: ArmEnd) -> Self {
        self.arms.push(Box::new(Arm { pattern, into }));
        self
    }

    pub fn build(self) -> Result<Match, RuleError> {
        let m = Match::new(self.kind, self.arms)?;
        Ok(m)
    }
}

fn test() -> Result<RuleTree, RuleError> {
    Ok(RuleTree::new(
        "test".into(),
        "testdesc".into(),
        MatchBuilder::with_arm(
            MatchKind::IpVer,
            Pattern::Equal(FieldValue::IpVer(super::IpVer::V4)),
            ArmEnd::Match(
                MatchBuilder::with_arm(
                    MatchKind::SrcIp,
                    Pattern::Glob(FieldValue::Ip(super::IpGlobbable::new([Octet::Value(192), Octet::Value(168), Octet::Any, Octet::Any]))), ArmEnd::Verdict(Verdict::Allow)
                ).build()?
            )
        ).arm(Pattern::Equal(FieldValue::IpVer(IpVer::V6)), ArmEnd::Verdict(Verdict::Drop)
        ).arm(
            Pattern::Or(vec![
                Pattern::Comparison(Operation::Greater, FieldValue::DayOfWeek(Weekday::Wed)),
                Pattern::Equal(FieldValue::DayOfWeek(Weekday::Mon)),
            ]),
            ArmEnd::Verdict(Verdict::Drop),
        )
        .build()?,
    ))
}
