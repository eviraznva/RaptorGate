#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatProtoDummy {
    Any,
    Tcp,
    Udp,
    Icmp,
}

impl NatProtoDummy {
    pub fn matches(self, other: L4Proto) -> bool {
        matches!(
            (self, other),
            (NatProtoDummy::Any, _)
                | (NatProtoDummy::Tcp, L4Proto::Tcp)
                | (NatProtoDummy::Udp, L4Proto::Udp)
                | (NatProtoDummy::Icmp, L4Proto::Icmp)
        )
    }

    pub fn has_ports(self) -> bool {
        matches!(self, NatProtoDummy::Tcp | NatProtoDummy::Udp | NatProtoDummy::Any)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4Proto {
    Tcp,
    Udp,
    Icmp,
}

impl L4Proto {
    pub fn has_ports(self) -> bool {
        matches!(self, L4Proto::Tcp | L4Proto::Udp)
    }
}