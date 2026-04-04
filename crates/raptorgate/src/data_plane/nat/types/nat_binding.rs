use std::time::Instant;

use crate::data_plane::nat::types::flow_tuple::FlowTuple;

/// Struktura reprezentująca powiązanie NAT:
/// Przechowuje informacje o translacji dla danego połączenia,
/// w tym oryginalne i przetłumaczone, przydzielony port oraz czasy utworzenia i wygaśnięcia powiązania.

#[derive(Debug, Clone)]
pub struct NatBinding {
    pub binding_id: u64,
    pub rule_id: String,
    pub original_forward: FlowTuple,
    pub translated_forward: FlowTuple,
    pub original_reply: FlowTuple,
    pub translated_reply: FlowTuple,
    pub allocated_port: Option<u16>,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub expires_at: Instant,
}
