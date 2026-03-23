use std::net::IpAddr;
use std::collections::HashSet;

use crate::policy::nat::port_range::PortRange;
use crate::data_plane::nat::types::flow_tuple::L4Proto;

pub struct PortStore {
    leased_ports: HashSet<(IpAddr, L4Proto, u16)>,
    default_pat_pool: PortRange,
}

impl PortStore {
    pub fn new(default_pat_pool: PortRange) -> Self {
        Self {
            leased_ports: HashSet::new(),
            default_pat_pool,
        }
    }

    pub fn add(&mut self, public_ip: IpAddr, proto: L4Proto, original_port: u16, pool: Option<PortRange>) 
        -> Option<u16> 
    {
        if !proto.has_ports() {
            return Some(original_port);
        }

        let preferred = (public_ip, proto, original_port);

        if !self.leased_ports.contains(&preferred) {
            self.leased_ports.insert(preferred);
            return Some(original_port);
        }

        let pool = pool.unwrap_or(self.default_pat_pool);

        for port in pool.start()..=pool.end() {
            let candidate = (public_ip, proto, port);
            
            if !self.leased_ports.contains(&candidate) {
                self.leased_ports.insert(candidate);
                return Some(port);
            }
        }

        None
    }

    pub fn delete(&mut self, public_ip: IpAddr, proto: L4Proto, port: u16) {
        self.leased_ports.remove(&(public_ip, proto, port));
    }

    pub fn clear(&mut self) {
        self.leased_ports.clear();
    }
}