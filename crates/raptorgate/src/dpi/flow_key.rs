use std::net::IpAddr;

use unordered_pair::UnorderedPair;

// Dwukierunkowy klucz sesji dla DPI (IP+port).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FlowKey {
    endpoints: UnorderedPair<FlowEndpoint>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
struct FlowEndpoint {
    ip: IpAddr,
    port: u16,
}

impl FlowKey {
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            endpoints: UnorderedPair::from((
                FlowEndpoint { ip: src_ip, port: src_port },
                FlowEndpoint { ip: dst_ip, port: dst_port },
            )),
        }
    }
}
