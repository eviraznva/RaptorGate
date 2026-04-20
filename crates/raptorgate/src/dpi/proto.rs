// Protokół warstwy aplikacji rozpoznany przez DPI, niezależnie od portu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppProto {
    Http,
    Tls,
    Dns,
    Ssh,
    Ftp,
    Smtp,
    Rdp,
    Smb,
    Quic,
    Unknown,
}

impl std::fmt::Display for AppProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AppProto::Http => "http",
            AppProto::Tls => "tls",
            AppProto::Dns => "dns",
            AppProto::Ssh => "ssh",
            AppProto::Ftp => "ftp",
            AppProto::Smtp => "smtp",
            AppProto::Rdp => "rdp",
            AppProto::Smb => "smb",
            AppProto::Quic => "quic",
            AppProto::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}
