use super::AppProto;
use super::parsers::dns::DnsRecordType;

// Decyzja dotycząca sesji TLS wyliczona przez runtime inspekcji.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsAction {
    Intercept,
    Bypass,
    Block,
}

// Metadane zebrane przez klasyfikator DPI dla pojedynczej sesji.
// Uzupełniane inkrementalnie podczas inspekcji pierwszych pakietów.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DpiContext {
    pub app_proto: Option<AppProto>,
    pub tls_sni: Option<String>,
    pub tls_ech_detected: bool,
    pub tls_version: Option<u16>,
    pub http_host: Option<String>,
    pub http_method: Option<String>,
    pub http_user_agent: Option<String>,
    pub http_content_type: Option<String>,
    pub dns_query_name: Option<String>,
    pub dns_query_type: Option<DnsRecordType>,
    pub dns_is_response: Option<bool>,
    pub dns_answer_count: u16,
    pub dns_answer_types: Vec<DnsRecordType>,
    pub dns_authority_count: u16,
    pub dns_authority_types: Vec<DnsRecordType>,
    pub dns_additional_count: u16,
    pub dns_additional_types: Vec<DnsRecordType>,
    pub dns_has_opt: bool,
    pub dns_dnssec_ok: bool,
    pub dns_authentic_data: bool,
    pub dns_checking_disabled: bool,
    pub dns_rcode: u16,
    pub dns_has_dnssec_records: bool,
    pub dns_response_size: u16,
    pub dns_has_ech_hints: bool,
    pub ftp_data_endpoint: Option<FtpDataEndpoint>,
    pub smtp_starttls: bool,
    pub ssh_proto_version: Option<String>,
    pub ssh_software: Option<String>,
    pub decrypted: bool,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ips_match: Option<IpsMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsMatch {
    pub signature_name: String,
    pub severity: String,
    pub blocked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpRewriteKind {
    Port,
    Pasv,
    Eprt { delimiter: u8 },
    Epsv { delimiter: u8 },
}

impl FtpRewriteKind {
    pub fn is_active_command(self) -> bool {
        matches!(self, Self::Port | Self::Eprt { .. })
    }
}

// Dane z odpowiedzi FTP PORT/PASV/EPSV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpDataEndpoint {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub rewrite_kind: FtpRewriteKind,
}
