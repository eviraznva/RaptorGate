use ipnet::IpNet;
use std::net::IpAddr;
use etherparse::SlicedPacket;

use crate::data_plane::nat::types::port_range_dummy::PortRangeDummy;
use crate::data_plane::nat::types::nat_proto_dummy::{L4Proto, NatProtoDummy};

#[derive(Debug, Clone)]
pub struct RuleMatchDummy {
    pub in_interface: Option<String>,
    pub out_interface: Option<String>,
    pub in_zone: Option<String>,
    pub out_zone: Option<String>,
    pub src_cidr: Option<IpNet>,
    pub dst_cidr: Option<IpNet>,
    pub proto: Option<NatProtoDummy>,
    pub src_ports: Option<PortRangeDummy>,
    pub dst_ports: Option<PortRangeDummy>,
}

impl RuleMatchDummy {
    pub fn matches_packet(
        &self,
        pkt: &SlicedPacket<'_>,
        in_interface: Option<&str>,
        out_interface: Option<&str>,
        in_zone: Option<&str>,
        out_zone: Option<&str>,
    ) -> bool {
        if let Some(expected) = &self.in_interface {
            if in_interface != Some(expected.as_str()) {
                return false;
            }
        }

        if let Some(expected) = &self.out_interface {
            if out_interface != Some(expected.as_str()) {
                return false;
            }
        }

        if let Some(expected) = &self.in_zone {
            if in_zone != Some(expected.as_str()) {
                return false;
            }
        }

        if let Some(expected) = &self.out_zone {
            if out_zone != Some(expected.as_str()) {
                return false;
            }
        }

        let src_ip = match packet_src_ip(pkt) {
            Some(ip) => ip,
            None => return false,
        };
        
        if let Some(cidr) = &self.src_cidr {
            if !cidr.contains(&src_ip) {
                return false;
            }
        }

        let dst_ip = match packet_dst_ip(pkt) {
            Some(ip) => ip,
            None => return false,
        };
        
        if let Some(cidr) = &self.dst_cidr {
            if !cidr.contains(&dst_ip) {
                return false;
            }
        }

        let proto = match packet_proto(pkt) {
            Some(proto) => proto,
            None => return false,
        };
        
        if let Some(expected) = self.proto {
            if !expected.matches(proto) {
                return false;
            }
        }

        if !proto.has_ports() {
            return self.src_ports.is_none() && self.dst_ports.is_none();
        }

        let (src_port, dst_port) = match packet_ports(pkt) {
            Some(ports) => ports,
            None => return false,
        };

        if let Some(range) = &self.src_ports {
            if !range.contains(src_port) {
                return false;
            }
        }

        if let Some(range) = &self.dst_ports {
            if !range.contains(dst_port) {
                return false;
            }
        }

        true
    }
}

fn packet_src_ip(pkt: &SlicedPacket<'_>) -> Option<IpAddr> {
    match pkt.net.as_ref()? {
        etherparse::NetSlice::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.header().source_addr())),
        etherparse::NetSlice::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.header().source_addr())),
        _ => None,
    }
}

fn packet_dst_ip(pkt: &SlicedPacket<'_>) -> Option<IpAddr> {
    match pkt.net.as_ref()? {
        etherparse::NetSlice::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.header().destination_addr())),
        etherparse::NetSlice::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.header().destination_addr())),
        _ => None,
    }
}

fn packet_proto(pkt: &SlicedPacket<'_>) -> Option<L4Proto> {
    match pkt.transport.as_ref()? {
        etherparse::TransportSlice::Tcp(_) => Some(L4Proto::Tcp),
        etherparse::TransportSlice::Udp(_) => Some(L4Proto::Udp),
        etherparse::TransportSlice::Icmpv4(_) | etherparse::TransportSlice::Icmpv6(_) => {
            Some(L4Proto::Icmp)
        }
    }
}

fn packet_ports(pkt: &SlicedPacket<'_>) -> Option<(u16, u16)> {
    match pkt.transport.as_ref()? {
        etherparse::TransportSlice::Tcp(tcp) => Some((tcp.source_port(), tcp.destination_port())),
        etherparse::TransportSlice::Udp(udp) => Some((udp.source_port(), udp.destination_port())),
        _ => None,
    }
}
