/// Enum reprezentujący protokoły warstwy 4 (transportowej):
/// - Tcp: protokół TCP
/// - Udp: protokół UDP
/// - Icmp: protokół ICMP

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4Proto {
    Tcp,
    Udp,
    Icmp,
}

impl L4Proto {
    /// Zwraca true, jeśli protokół posiada porty (TCP lub UDP)
    pub fn has_ports(self) -> bool {
        matches!(self, L4Proto::Tcp | L4Proto::Udp)
    }
}
