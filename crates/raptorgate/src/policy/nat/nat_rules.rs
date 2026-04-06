use crate::policy::nat::nat_rule::NatRule;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NatRules {
    rules: Vec<NatRule>,
}

impl NatRules {
    pub fn new(mut rules: Vec<NatRule>) -> Self {
        rules.sort_by_key(NatRule::priority);

        Self { rules }
    }

    pub fn rules(&self) -> &[NatRule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
