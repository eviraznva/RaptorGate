use std::time::{SystemTime, UNIX_EPOCH};
use derive_more::{Display, From};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

pub trait Frame {
    fn ip_ver(&self) -> IpVer;
    fn src_ip(&self) -> IP;
    fn dst_ip(&self) -> IP;
    fn protocol(&self) -> Protocol;
    fn src_port(&self) -> Option<Port>;
    fn dst_port(&self) -> Option<Port>;
    fn hour(&self) -> Hour;
    fn day_of_week(&self) -> Weekday;
}

#[derive(Debug, Clone, Copy, From, Display, PartialEq, Eq, PartialOrd, Ord)]
pub struct Port(u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IP {
    octets: [Octet; 4],
}

impl IP {
    pub fn new(octets: [Octet; 4]) -> Self {
        Self { octets }
    }
}

impl TryFrom<String> for IP {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<&str> for IP {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut octets = [Octet::Value(0); 4];
        let mut parts = value.split('.');

        for octet in &mut octets {
            let part = parts.next().ok_or("invalid IPv4 address")?;
            *octet = match part {
                "*" => Octet::Any,
                _ => Octet::Value(part.parse::<u8>().map_err(|_| "invalid IPv4 octet")?),
            };
        }

        if parts.next().is_some() {
            return Err("invalid IPv4 address");
        }

        Ok(Self::new(octets))
    }
}
impl std::fmt::Display for IP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
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

impl Eq for Octet {}

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq)]
pub enum IpVer {
    V4,
    V6,
}

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol { Tcp, Udp, Icmp }
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Weekday { Mon, Tue, Wed, Thu, Fri, Sat, Sun }
pub(crate) struct RealFrame {
    ip_ver: IpVer,
    src_ip: IP,
    dst_ip: IP,
    protocol: Protocol,
    src_port: Option<Port>, 
    dst_port: Option<Port>,
    hour: Hour,
    day_of_week: Weekday,
}

impl RealFrame {
    pub(crate) fn from_sliced(packet: &SlicedPacket) -> Option<Self> {
        let (ip_ver, src_ip, dst_ip) = match &packet.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let h = ipv4.header();
                let s = h.source();
                let d = h.destination();
                (
                    IpVer::V4,
                    IP::new([Octet::Value(s[0]), Octet::Value(s[1]), Octet::Value(s[2]), Octet::Value(s[3])]),
                    IP::new([Octet::Value(d[0]), Octet::Value(d[1]), Octet::Value(d[2]), Octet::Value(d[3])]),
                )
            }
            // No IPv6 for now
            _ => return None,
        };

        let (protocol, src_port, dst_port) = match &packet.transport {
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

        Some(Self { ip_ver, src_ip, dst_ip, protocol, src_port, dst_port, hour, day_of_week })
    }
}

impl Frame for RealFrame {
    fn ip_ver(&self) -> IpVer { self.ip_ver }
    fn src_ip(&self) -> IP { self.src_ip }
    fn dst_ip(&self) -> IP { self.dst_ip }
    fn protocol(&self) -> Protocol { self.protocol }
    fn src_port(&self) -> Option<Port> { self.src_port }
    fn dst_port(&self) -> Option<Port> { self.dst_port }
    fn hour(&self) -> Hour { self.hour }
    fn day_of_week(&self) -> Weekday { self.day_of_week }
}
