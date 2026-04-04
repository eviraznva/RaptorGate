use ipnet::IpNet;

use crate::policy::nat::port_range::PortRange;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatProtocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatAction {
    Pat,
    Dnat,
    Snat,
    Masquerade,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatRule {
    id: String,
    priority: u32,
    in_interface: Option<String>,
    out_interface: Option<String>,
    in_zone: Option<String>,
    out_zone: Option<String>,
    src_cidr: Option<IpNet>,
    dst_cidr: Option<IpNet>,
    protocol: Option<NatProtocol>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    action: NatAction,
}

impl NatRule {
    pub fn new(
        id: String,
        priority: u32,
        in_interface: Option<String>,
        out_interface: Option<String>,
        in_zone: Option<String>,
        out_zone: Option<String>,
        src_cidr: Option<IpNet>,
        dst_cidr: Option<IpNet>,
        protocol: Option<NatProtocol>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        action: NatAction,
    ) -> Self {
        Self {
            id,
            priority,
            in_interface,
            out_interface,
            in_zone,
            out_zone,
            src_cidr,
            dst_cidr,
            protocol,
            src_port,
            dst_port,
            action,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn priority(&self) -> u32 {
        self.priority
    }
    pub fn in_interface(&self) -> Option<&str> {
        self.in_interface.as_ref().map(|s| s.as_str())
    }
    pub fn out_interface(&self) -> Option<&str> {
        self.out_interface.as_ref().map(|s| s.as_str())
    }
    pub fn in_zone(&self) -> Option<&str> {
        self.in_zone.as_ref().map(|s| s.as_str())
    }
    pub fn out_zone(&self) -> Option<&str> {
        self.out_zone.as_ref().map(|s| s.as_str())
    }
    pub fn src_cidr(&self) -> Option<IpNet> {
        self.src_cidr
    }
    pub fn dst_cidr(&self) -> Option<IpNet> {
        self.dst_cidr
    }
    pub fn protocol(&self) -> Option<NatProtocol> {
        self.protocol
    }
    pub fn src_port(&self) -> Option<u16> {
        self.src_port
    }
    pub fn dst_port(&self) -> Option<u16> {
        self.dst_port
    }
    pub fn action(&self) -> NatAction {
        self.action.clone()
    }
}
