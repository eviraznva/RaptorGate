use std::hash::Hash;
use std::net::IpAddr;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)] // Enkoduj enum jako 1 bajt
pub enum Protocol {
    Tcp = 6,
    Udp = 17,
    Icmp = 1,
    IcmpV6 = 58,
}

impl Protocol {
    pub fn from_ip_protocol(num: u8) -> Option<Self> {
        match num {
            6 => Some(Protocol::Tcp),
            17 => Some(Protocol::Udp),
            1 => Some(Protocol::Icmp),
            58 => Some(Protocol::IcmpV6),
            _ => None,
        }
    }

    pub fn has_ports(&self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Original,
    Reply,
}

impl Direction {
    pub fn opposite(&self) -> Self {
        match self {
            Self::Original => Self::Reply,
            Self::Reply => Self::Original,
        }
    }
}

// Struktura reprezentująca unikalny identyfikator flow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,

    pub dst_ip: IpAddr,
    pub dst_port: u16,

    pub zone: u16,
    pub protocol: Protocol,
}

impl FlowTuple {
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16, protocol: Protocol) -> Self {
        Self { src_ip, src_port, dst_ip, dst_port, zone: 0, protocol }
    }

    pub fn with_zone(mut self, zone: u16) -> Self {
        self.zone = zone;
        
        self
    }

    pub fn invert(&self) -> Self {
        match self.protocol {
            Protocol::Icmp | Protocol::IcmpV6 => self.invert_icmp(),
            
            _ => Self {
                src_ip: self.dst_ip,
                src_port: self.dst_port,
                
                dst_ip: self.src_ip,
                dst_port: self.src_port,
                
                zone: self.zone,
                protocol: self.protocol,
            },
        }
    }

    pub fn from_sliced(pkt: &SlicedPacket) -> Option<Self> {
        let (src_ip, dst_ip) = match pkt.net.as_ref()? {
            NetSlice::Ipv4(ipv4) => (
                IpAddr::V4(ipv4.header().source_addr()),
                IpAddr::V4(ipv4.header().destination_addr())
            ),

            NetSlice::Ipv6(ipv6) => (
                IpAddr::V6(ipv6.header().source_addr()),
                IpAddr::V6(ipv6.header().destination_addr())
            ),

            _ => return None,
        };

        let (src_port, dst_port, proto) = match pkt.transport.as_ref()? {
            TransportSlice::Tcp(tcp) => (
                tcp.source_port(),
                tcp.destination_port(),
                Protocol::Tcp,
            ),

            TransportSlice::Udp(udp) => (
                udp.source_port(),
                udp.destination_port(),
                Protocol::Udp,
            ),

            TransportSlice::Icmpv4(icmp) => {
                let id = Self::icmp_echo_id(icmp.bytes5to8()).unwrap_or(0);
                
                let bytes = icmp.header().to_bytes();
                let type_code = (u16::from(bytes[0]) << 8) | u16::from(bytes[1]);
                
                (id, type_code, Protocol::Icmp)
            },

            TransportSlice::Icmpv6(icmp) => {
                let id = Self::icmp_echo_id(icmp.bytes5to8()).unwrap_or(0);
                
                let bytes = icmp.header().to_bytes();
                let type_code = (u16::from(bytes[0]) << 8) | u16::from(bytes[1]);
                
                (id, type_code, Protocol::IcmpV6)
            },
        };

        Some(Self { src_ip, src_port, dst_ip, dst_port, zone: 0, protocol: proto })
    }
    
    pub fn lookup_keys(&self) -> [Self; 2] {
        [*self, self.invert()]
    }

    fn invert_icmp(&self) -> Self {
        let req_type = (self.dst_port >> 8) as u8;
        let code = (self.dst_port & 0xff) as u8;
        
        let reply_type = Self::invert_icmp_type(self.protocol, req_type);
        
        let reply_dst_port = (u16::from(reply_type) << 8) | u16::from(code);

        Self {
            src_ip: self.dst_ip,
            src_port: self.src_port,
            dst_ip: self.src_ip,
            dst_port: reply_dst_port,
            protocol: self.protocol,
            zone: self.zone,
        }
    }

    fn invert_icmp_type(proto: Protocol, t: u8) -> u8 {
        match proto {
            Protocol::Icmp => match t {
                8 => 0, 0 => 8,         // Echo
                13 => 14, 14 => 13,     // Timestamp
                15 => 16, 16 => 15,     // Information
                17 => 18, 18 => 17,     // Address mask
                other => other,         // error types — bez inwersji
            },
            
            Protocol::IcmpV6 => match t {
                128 => 129, 129 => 128, // Echo
                130 => 131, 131 => 130, // MLD query/report
                132 => 133, 133 => 132,
                other => other,
            },
            
            _ => t,
        }
    }
    
    fn icmp_echo_id(bytes: [u8; 4]) -> Option<u16> {
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn t() -> FlowTuple {
        FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            Protocol::Udp,
        )
    }

    #[test]
    fn invert_swaps_src_and_dst() {
        let original = t();
        let reply = original.invert();
        
        assert_eq!(reply.src_ip, original.dst_ip);
        assert_eq!(reply.dst_ip, original.src_ip);
        assert_eq!(reply.src_port, original.dst_port);
        assert_eq!(reply.dst_port, original.src_port);
        assert_eq!(reply.protocol, original.protocol);
    }

    #[test]
    fn invert_is_involution() {
        let original = t();
        
        assert_eq!(original.invert().invert(), original);
    }

    #[test]
    fn lookup_keys_returns_both_directions() {
        let original = t();
        let keys = original.lookup_keys();
        
        assert_eq!(keys[0], original);
        assert_eq!(keys[1], original.invert());
    }

    #[test]
    fn l4proto_round_trip() {
        for p in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp, Protocol::IcmpV6] {
            assert_eq!(Protocol::from_ip_protocol(p as u8), Some(p));
        }
        
        assert_eq!(Protocol::from_ip_protocol(132), None); // SCTP
    }

    #[test]
    fn opposite_direction_round_trip() {
        assert_eq!(Direction::Original.opposite(), Direction::Reply);
        assert_eq!(Direction::Reply.opposite(), Direction::Original);
        assert_eq!(Direction::Original.opposite().opposite(), Direction::Original);
    }

    #[test]
    fn invert_icmp_swaps_type() {
        let req = FlowTuple {
            src_ip: IpAddr::V4(Ipv4Addr::new(10,0,0,1)),
            src_port: 42,
            dst_ip: IpAddr::V4(Ipv4Addr::new(8,8,8,8)),
            dst_port: 0x0800,  // type=8, code=0
            protocol: Protocol::Icmp,
            zone: 0,
        };
        
        let rep = req.invert();
        
        assert_eq!(rep.src_port, 42);
        assert_eq!(rep.dst_port, 0x0000);
    }
}