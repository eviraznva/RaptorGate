use crate::data_plane::nat::types::nat_binding_direction::NatBindingDirection;

#[derive(Debug)]
pub enum NatOutcome {
    NoMatch,
    AppliedExisting {
        binding_id: u64,
        direction: NatBindingDirection,
    },
    Created {
        binding_id: u64,
        rule_id: String,
    },
}
