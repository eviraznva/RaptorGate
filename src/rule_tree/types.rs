use derive_more::{Debug, Display, Eq, Error, From};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, From, Display, PartialEq, PartialOrd, Hash, Eq, Ord)]
pub struct Port(u16);

impl From<Port> for u16 {
    fn from(p: Port) -> u16 {
        p.0
    }
}

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
    #[display("*")]
    Any,
    #[display("{}", _0)]
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
    #[display("v4")]
    V4,
    #[display("v6")]
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Protocol::Tcp  => "tcp",
            Protocol::Udp  => "udp",
            Protocol::Icmp => "icmp",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Display, Clone, Copy, PartialEq, PartialOrd)]
pub enum Weekday {
    #[display("monday")]
    Mon,
    #[display("tuesday")]
    Tue,
    #[display("wednesday")]
    Wed,
    #[display("thursday")]
    Thu,
    #[display("friday")]
    Fri,
    #[display("saturday")]
    Sat,
    #[display("sunday")]
    Sun,
}

/// Pre-computed arrival time fields extracted from a packet's `SystemTime`.
/// Passed to `PolicyEvaluator::evaluate` so time-based rules can be tested
/// with deterministic values.
pub struct ArrivalInfo {
    pub hour: Hour,
    pub day_of_week: Weekday,
}

impl ArrivalInfo {
    pub fn from_time(time: &SystemTime) -> Self {
        let secs = time
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
        Self { hour, day_of_week }
    }
}
