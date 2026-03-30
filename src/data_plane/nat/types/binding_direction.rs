/// Enum określający kierunek powiązania NAT:
/// - Forward: translacja w kierunku oryginalnym (np. od klienta do serwera)
/// - Reply: translacja w kierunku odpowiedzi (np. od serwera do klienta)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatBindingDirection {
    Forward,
    Reply,
}
