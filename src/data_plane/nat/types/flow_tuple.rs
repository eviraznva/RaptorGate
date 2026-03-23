use std::net::IpAddr;

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: L4Proto,
}

impl FlowTuple {
    pub fn reversed(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            proto: self.proto,
        }
    }
}
