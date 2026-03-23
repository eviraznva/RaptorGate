use derive_more::{Debug, Display, Eq, Error, From};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use std::{net::IpAddr, time::{SystemTime, UNIX_EPOCH}};

pub(crate) trait Frame {
    fn ip_ver(&self) -> IpVer;
    fn src_ip(&self) -> IpAddr;
    fn dst_ip(&self) -> IpAddr;
    fn protocol(&self) -> Protocol;
    fn src_port(&self) -> Option<Port>;
    fn dst_port(&self) -> Option<Port>;
    fn hour(&self) -> Hour;
    fn day_of_week(&self) -> Weekday;
    //TODO: temporary hack
    fn transport_data(&'_ self) -> Option<&'_ TransportSlice<'_>>;
}

#[derive(Debug, Clone, Copy, From, Display, PartialEq, PartialOrd, Hash, Eq, Ord)]
pub struct Port(u16);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IpGlobbable {
    octets: [Octet; 4],
}

impl IpGlobbable {
    pub fn new(octets: [Octet; 4]) -> Self {
        Self { octets }
    }

    pub fn octets(&self) -> [Octet; 4] {
        self.octets
    }
}

impl From<Port> for u16 {
    fn from(p: Port) -> u16 {
        p.0
    }
}

#[derive(Error, Debug, Display)]
pub enum IPError {
    ParseFromStringError,
}

impl TryFrom<String> for IpGlobbable {
    type Error = IPError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() != 4 {
            return Err(IPError::ParseFromStringError);
        }

        let mut octets: [Octet; 4] = [Octet::Value(0); 4];
        for (i, part) in parts.into_iter().enumerate() {
            match part.trim().parse::<u8>() {
                Ok(n) => octets[i] = Octet::Value(n),
                Err(_) => return Err(IPError::ParseFromStringError),
            }
        }

        Ok(IpGlobbable::new(octets))
    }
}

impl From<IpAddr> for IpGlobbable {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                IpGlobbable::new([
                    Octet::Value(octets[0]),
                    Octet::Value(octets[1]),
                    Octet::Value(octets[2]),
                    Octet::Value(octets[3]),
                ])
            }
            _ => todo!("IPv6 not supported yet"),
        }
    }
}

impl std::fmt::Display for IpGlobbable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0], self.octets[1], self.octets[2], self.octets[3],
        )
    }
}

#[derive(Debug, Clone, Copy, Display)]
pub enum Octet {
    Any,
    Value(u8),
}

impl PartialEq for Octet {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Octet::Value(a), Octet::Value(b)) => a == b,
            _ => true,
        }
    }
}

#[derive(Debug, Display, Clone, Copy, PartialEq)]
pub enum IpVer {
    V4,
    V6,
}

#[derive(Debug, Display, Clone, Copy, PartialEq, PartialOrd)]
pub struct Hour(u8);

impl TryFrom<u8> for Hour {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0..=23 => Ok(Self(value)),
            _ => Err("value not in day range"),
        }
    }
}

#[derive(Debug, Display, Clone, Copy, PartialEq, PartialOrd)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}
#[derive(Debug, Display, Clone, Copy, PartialEq, PartialOrd)]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

// TODO: encode arrival time as `Instant`
pub struct RealFrame<'a> {
    ip_ver: IpVer,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: Protocol,
    src_port: Option<Port>,
    dst_port: Option<Port>,
    hour: Hour,
    day_of_week: Weekday,
    // TODO: temporary
    transport_data: Option<TransportSlice<'a>>
}

impl<'a> RealFrame<'a> {
    pub fn from_sliced(packet: &SlicedPacket<'a>) -> Option<Self> {
        let (ip_ver, src_ip, dst_ip) = match &packet.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let h = ipv4.header();
                (
                    IpVer::V4,
                    IpAddr::V4(h.source_addr()),
                    IpAddr::V4(h.destination_addr()),
                )
            }
            // No IPv6 for now
            _ => return None,
        };

        let transport = &packet.transport;
        let (protocol, src_port, dst_port) = match transport {
            Some(TransportSlice::Tcp(tcp)) => (
                Protocol::Tcp,
                Some(Port::from(tcp.source_port())),
                Some(Port::from(tcp.destination_port())),
            ),
            Some(TransportSlice::Udp(udp)) => (
                Protocol::Udp,
                Some(Port::from(udp.source_port())),
                Some(Port::from(udp.destination_port())),
            ),
            Some(TransportSlice::Icmpv4(_)) => (Protocol::Icmp, None, None),
            _ => return None,
        };

        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let hour = Hour::try_from(((secs % 86400) / 3600) as u8)
            .unwrap_or_else(|_| Hour::try_from(0).unwrap());

        // Epoch (1970-01-01) was a Thursday.
        let day_of_week = match (secs / 86400) % 7 {
            0 => Weekday::Thu,
            1 => Weekday::Fri,
            2 => Weekday::Sat,
            3 => Weekday::Sun,
            4 => Weekday::Mon,
            5 => Weekday::Tue,
            _ => Weekday::Wed,
        };

        Some(Self {
            ip_ver,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            hour,
            day_of_week,
            transport_data: transport.clone(),
        })
    }
}

impl Frame for RealFrame<'_> {
    fn ip_ver(&self) -> IpVer {
        self.ip_ver
    }
    fn src_ip(&self) -> IpAddr {
        self.src_ip
    }
    fn dst_ip(&self) -> IpAddr {
        self.dst_ip
    }
    fn protocol(&self) -> Protocol {
        self.protocol
    }
    fn src_port(&self) -> Option<Port> {
        self.src_port
    }
    fn dst_port(&self) -> Option<Port> {
        self.dst_port
    }
    fn hour(&self) -> Hour {
        self.hour
    }
    fn day_of_week(&self) -> Weekday {
        self.day_of_week
    }

    fn transport_data(&'_ self) -> Option<&'_ TransportSlice<'_>> {
        self.transport_data.as_ref()
    }
}
