use derive_more::Display;

// Protokół warstwy aplikacji rozpoznany przez DPI, niezależnie od portu.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Hash)]
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
