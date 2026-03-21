use std::net::IpAddr;

use crate::data_plane::nat::types::nat_proto_dummy::L4Proto;

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