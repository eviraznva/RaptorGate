/// Enum określający etap przetwarzania pakietu przez silnik NAT:
/// - Prerouting: translacja przed routingiem (np. DNAT)
/// - Postrouting: translacja po routingiu (np. SNAT, MASQUERADE)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatStage {
    Prerouting,
    Postrouting,
}
