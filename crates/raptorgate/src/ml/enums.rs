use crate::dpi::AppProto;
use crate::dpi::parsers::dns::DnsRecordType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum MlAppProto {
    #[default]
    Unknown = 0,
    Tls = 1,
    Http = 2,
    Dns = 3,
    Ssh = 4,
    Quic = 5,
    Smtp = 6,
    Ftp = 7,
    Rdp = 8,
    Smb = 9,
    Other = 10,
}

impl MlAppProto {
    pub fn to_f32(self) -> f32 {
        self as u8 as f32
    }
}

impl From<AppProto> for MlAppProto {
    fn from(value: AppProto) -> Self {
        match value {
            AppProto::Tls => Self::Tls,
            AppProto::Http => Self::Http,
            AppProto::Dns => Self::Dns,
            AppProto::Ssh => Self::Ssh,
            AppProto::Quic => Self::Quic,
            AppProto::Smtp => Self::Smtp,
            AppProto::Ftp => Self::Ftp,
            AppProto::Rdp => Self::Rdp,
            AppProto::Smb => Self::Smb,
            AppProto::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum MlTlsVersion {
    #[default]
    Unknown = 0,
    Ssl3 = 1,
    Tls10 = 2,
    Tls11 = 3,
    Tls12 = 4,
    Tls13 = 5,
}

impl MlTlsVersion {
    pub fn to_f32(self) -> f32 {
        self as u8 as f32
    }
    
    pub fn from_raw(v: u16) -> Self {
        match v {
            0x0300 => Self::Ssl3,
            0x0301 => Self::Tls10,
            0x0302 => Self::Tls11,
            0x0303 => Self::Tls12,
            0x0304 => Self::Tls13,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum MlHttpMethod {
    #[default]
    None = 0,
    Get = 1,
    Post = 2,
    Put = 3,
    Delete = 4,
    Head = 5,
    Options = 6,
    Connect = 7,
    Other = 8,
}

impl MlHttpMethod {
    pub fn to_f32(self) -> f32 {
        self as u8 as f32
    }

    pub fn from_str_case_insensitive(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "CONNECT" => Self::Connect,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum MlQtype {
    #[default]
    None = 0,
    A = 1,
    Aaaa = 2,
    Cname = 3,
    Mx = 4,
    Txt = 5,
    Ns = 6,
    Ptr = 7,
    Srv = 8,
    Soa = 9,
    Https = 10,
    Svcb = 11,
    Any = 12,
    Axfr = 13,
    Other = 14,
}

impl MlQtype {
    pub fn to_f32(self) -> f32 {
        self as u8 as f32
    }
}

impl From<DnsRecordType> for MlQtype {
    fn from(value: DnsRecordType) -> Self {
        match value {
            DnsRecordType::A => Self::A,
            DnsRecordType::Aaaa => Self::Aaaa,
            DnsRecordType::Cname => Self::Cname,
            DnsRecordType::Mx => Self::Mx,
            DnsRecordType::Txt => Self::Txt,
            DnsRecordType::Ns => Self::Ns,
            DnsRecordType::Srv => Self::Srv,
            DnsRecordType::Soa => Self::Soa,
            DnsRecordType::Https => Self::Https,
            DnsRecordType::Svcb => Self::Svcb,
            DnsRecordType::Any => Self::Any,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum MlL4Proto {
    #[default]
    Other = 0,
    Tcp = 1,
    Udp = 2,
    Icmp = 3,
    Sctp = 4,
}

impl MlL4Proto {
    pub fn to_f32(self) -> f32 {
        self as u8 as f32
    }
    
    pub fn from_ip_proto(n: u8) -> Self {
        match n {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 | 58 => Self::Icmp,
            132 => Self::Sctp,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum MlPortClass {
    #[default]
    Unknown = 0,
    WellKnown = 1,
    Registered = 2,
    Dynamic = 3,
}

impl MlPortClass {
    pub fn to_f32(self) -> f32 {
        self as u8 as f32
    }

    pub fn from_port(port: u16) -> Self {
        match port {
            0 => Self::Unknown,
            1..=1023 => Self::WellKnown,
            1024..=49151 => Self::Registered,
            _ => Self::Dynamic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_proto_tls_maps() {
        assert_eq!(MlAppProto::from(AppProto::Tls), MlAppProto::Tls);
        assert_eq!(MlAppProto::from(AppProto::Unknown), MlAppProto::Unknown);
    }

    #[test]
    fn tls_version_from_raw() {
        assert_eq!(MlTlsVersion::from_raw(0x0303), MlTlsVersion::Tls12);
        assert_eq!(MlTlsVersion::from_raw(0x0304), MlTlsVersion::Tls13);
        assert_eq!(MlTlsVersion::from_raw(0x0000), MlTlsVersion::Unknown);
    }

    #[test]
    fn http_method_parses() {
        assert_eq!(MlHttpMethod::from_str_case_insensitive("get"), MlHttpMethod::Get);
        assert_eq!(MlHttpMethod::from_str_case_insensitive("PROPFIND"), MlHttpMethod::Other);
    }

    #[test]
    fn port_class_buckets() {
        assert_eq!(MlPortClass::from_port(443), MlPortClass::WellKnown);
        assert_eq!(MlPortClass::from_port(8080), MlPortClass::Registered);
        assert_eq!(MlPortClass::from_port(50000), MlPortClass::Dynamic);
    }

    #[test]
    fn l4_proto_from_ip() {
        assert_eq!(MlL4Proto::from_ip_proto(6), MlL4Proto::Tcp);
        assert_eq!(MlL4Proto::from_ip_proto(17), MlL4Proto::Udp);
        assert_eq!(MlL4Proto::from_ip_proto(255), MlL4Proto::Other);
    }
}
