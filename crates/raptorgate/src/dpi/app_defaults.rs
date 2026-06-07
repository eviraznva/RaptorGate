use crate::conntrack::tuple::Protocol;
use crate::dpi::AppProto;

pub fn is_default_service(app_proto: AppProto, protocol: Protocol, port: u16) -> bool {
    match (app_proto, protocol) {
        (AppProto::Http, Protocol::Tcp) => port == 80,
        (AppProto::Tls, Protocol::Tcp) => port == 443,
        (AppProto::Dns, Protocol::Udp | Protocol::Tcp) => port == 53,
        (AppProto::Ssh, Protocol::Tcp) => port == 22,
        (AppProto::Ftp, Protocol::Tcp) => port == 21,
        (AppProto::Smtp, Protocol::Tcp) => matches!(port, 25 | 587),
        (AppProto::Rdp, Protocol::Tcp) => port == 3389,
        (AppProto::Smb, Protocol::Tcp) => matches!(port, 139 | 445),
        (AppProto::Quic, Protocol::Udp) => port == 443,
        _ => false,
    }
}
