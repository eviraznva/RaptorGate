use std::net::IpAddr;

use bitflags::bitflags;

bitflags! {
      /// Flagi mówiące jakie pola w `NatRange` są obowiązkowe oraz jak wybierać port
      #[derive(Debug, Clone, Copy, PartialEq, Eq)]
      pub struct RangeFlags: u32 {
          const MAP_IPS         = 1 << 0;
          const PROTO_SPECIFIED = 1 << 1;
          const PROTO_RANDOM    = 1 << 2;
          const PROTO_RANDOM_FULLY = 1 << 3;
          const PERSISTENT      = 1 << 4;
      }
  }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStrategy {
    Persistent,
    Random,
    RandomFully,
}

impl PortStrategy {
    pub fn from_flags(f: RangeFlags) -> Self {
        if f.contains(RangeFlags::PROTO_RANDOM_FULLY) {
            Self::RandomFully
        } else if f.contains(RangeFlags::PROTO_RANDOM) {
            Self::Random
        } else {
            Self::Persistent
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatRange {
    pub flags: RangeFlags,
    pub min_ip: IpAddr,
    pub max_ip: IpAddr,
    pub min_port: u16,
    pub max_port: u16,
}

impl NatRange {
    /// Pojedynczy IP, pełen zakres portów (1024–65535)
    pub fn single_ip_default(ip: IpAddr) -> Self {
        Self {
            flags: RangeFlags::MAP_IPS | RangeFlags::PERSISTENT,
            min_ip: ip,
            max_ip: ip,
            min_port: 1024,
            max_port: 65535,
        }
    }

    /// Pojedynczy IP, jawny port (np. PAT — port forwarding)
    pub fn single_ip_port(ip: IpAddr, port: u16) -> Self {
        Self {
            flags: RangeFlags::MAP_IPS | RangeFlags::PROTO_SPECIFIED,
            min_ip: ip,
            max_ip: ip,
            min_port: port,
            max_port: port,
        }
    }

    /// Pojedynczy IP, zakres portów (np. SNAT)
    pub fn single_ip_port_range(ip: IpAddr, min_port: u16, max_port: u16) -> Self {
        Self {
            flags: RangeFlags::MAP_IPS | RangeFlags::PROTO_SPECIFIED | RangeFlags::PERSISTENT,
            min_ip: ip,
            max_ip: ip,
            min_port,
            max_port,
        }
    }

    pub fn port_strategy(&self) -> PortStrategy { PortStrategy::from_flags(self.flags) }

    pub fn port_specified(&self) -> bool { self.flags.contains(RangeFlags::PROTO_SPECIFIED) }

    pub fn port_span(&self) -> u32 {
        u32::from(self.max_port - self.min_port) + 1
    }

    /// Czy IP jest tylko jeden (min == max).
    pub fn single_ip(&self) -> bool { self.min_ip == self.max_ip }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn default_range_uses_ephemeral_ports_and_persistent_strategy() {
        let r = NatRange::single_ip_default(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
        
        assert_eq!(r.min_port, 1024);
        assert_eq!(r.max_port, 65535);
        assert_eq!(r.port_strategy(), PortStrategy::Persistent);
        assert!(r.single_ip());
    }

    #[test]
    fn explicit_port_range_specifies_proto() {
        let r = NatRange::single_ip_port(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8443);
        
        assert!(r.port_specified());
        assert_eq!(r.port_span(), 1);
    }

    #[test]
    fn port_span_matches_inclusive_count() {
        let r = NatRange::single_ip_port_range(IpAddr::V4(Ipv4Addr::new(1,1,1,1)), 1024, 1027);
        
        assert_eq!(r.port_span(), 4);
    }

    #[test]
    fn random_fully_flag_overrides_random() {
        let mut r = NatRange::single_ip_default(IpAddr::V4(Ipv4Addr::new(1,1,1,1)));
        r.flags |= RangeFlags::PROTO_RANDOM | RangeFlags::PROTO_RANDOM_FULLY;
        
        assert_eq!(r.port_strategy(), PortStrategy::RandomFully);
    }
}