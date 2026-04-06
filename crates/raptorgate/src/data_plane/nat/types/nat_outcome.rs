use crate::data_plane::nat::types::binding_direction::NatBindingDirection;

/// Enum opisujący możliwe rezultaty przetwarzania pakietu przez silnik NAT:
/// - NoMatch: brak dopasowania do reguły lub powiązania
/// - AppliedExisting: zastosowano istniejące powiązanie NAT (binding)
/// - Created: utworzono nowe powiązanie NAT na podstawie reguły
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
