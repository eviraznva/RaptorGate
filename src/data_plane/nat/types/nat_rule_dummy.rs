use crate::data_plane::nat::types::nat_kind_dummy::NatKindDummy;
use crate::data_plane::nat::types::rule_match_dummy::RuleMatchDummy;
use crate::data_plane::nat::types::nat_timeouts_dummy::NatTimeoutsDummy;

#[derive(Debug, Clone)]
pub struct NatRuleDummy {
    pub id: String,
    pub priority: u32,
    pub match_criteria: RuleMatchDummy,
    pub kind: NatKindDummy,
    pub timeouts: NatTimeoutsDummy,
}