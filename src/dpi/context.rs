use super::AppProto;

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
    pub dns_query_type: Option<u16>,
    pub dns_is_response: Option<bool>,
    pub dns_answer_count: u16,
    pub dns_answer_types: Vec<u16>,
    pub dns_response_size: u16,
    pub ftp_data_endpoint: Option<FtpDataEndpoint>,
    pub smtp_starttls: bool,
    pub ssh_proto_version: Option<String>,
    pub ssh_software: Option<String>,
}

// Dane z odpowiedzi FTP PORT/PASV/EPSV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpDataEndpoint {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
}
