use derive_more::Debug;
use nonempty::NonEmpty;

use crate::rule_tree::{
    Arm, ArmEnd, FieldValue, Hour, IpVer, MatchKind, Octet, Operation, Pattern, RuleError,
    RuleTree, Verdict, Weekday,
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
