use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use super::context::DpiContext;
use super::flow_key::FlowKey;
use super::parsers::{dns, http, ssh, tls};
use super::AppProto;

const MAX_INSPECT_BYTES: usize = 16_384;
const MAX_INSPECT_PACKETS: u8 = 5;

// Wynik inspekcji pakietu przez klasyfikator DPI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectResult {
    Done(DpiContext),
    NeedMore,
    Skipped,
}

// Stan inspekcji DPI dla pojedynczej sesji.
struct DpiSessionEntry {
    buffer: Vec<u8>,
    packets_seen: u8,
    result: Option<DpiContext>,
}

impl DpiSessionEntry {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            packets_seen: 0,
            result: None,
        }
    }
    fn limits_exceeded(&self) -> bool {
        self.buffer.len() >= MAX_INSPECT_BYTES || self.packets_seen >= MAX_INSPECT_PACKETS
    }

    fn append_payload(&mut self, payload: &[u8]) {
        let remaining = MAX_INSPECT_BYTES.saturating_sub(self.buffer.len());
        let to_copy = payload.len().min(remaining);
        self.buffer.extend_from_slice(&payload[..to_copy]);
        self.packets_seen += 1;
    }
}

// Klasyfikator DPI z per-session buforowaniem i zachłanną klasyfikacją.
pub struct DpiClassifier {
    sessions: Arc<DashMap<FlowKey, DpiSessionEntry>>,
}

impl DpiClassifier {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    // Inspekcja pakietu buforuje payload i próbuje klasyfikacji.
    pub fn inspect_packet(&self, packet: &SlicedPacket) -> InspectResult {
        let Some((key, payload)) = Self::extract_flow(packet) else {
            return InspectResult::Skipped;
        };

        if payload.is_empty() {
            return InspectResult::Skipped;
        }

        let mut entry = self.sessions.entry(key).or_insert_with(DpiSessionEntry::new);
        let session = entry.value_mut();

        if let Some(ref ctx) = session.result {
            return InspectResult::Done(ctx.clone());
        }

        session.append_payload(payload);

        if let Some(ctx) = Self::try_classify(&session.buffer) {
            session.result = Some(ctx.clone());
            return InspectResult::Done(ctx);
        }

        if session.limits_exceeded() {
            let ctx = DpiContext {
                app_proto: Some(AppProto::Unknown),
                ..Default::default()
            };
            session.result = Some(ctx.clone());
            return InspectResult::Done(ctx);
        }

        InspectResult::NeedMore
    }

    // Usuwa stan sesji DPI.
    pub fn remove_session(&self, src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) {
        let key = FlowKey::new(src_ip, src_port, dst_ip, dst_port);
        self.sessions.remove(&key);
    }

    // Liczba aktywnych sesji DPI. Można użyć później do trackingu.
    fn session_count(&self) -> usize {
        self.sessions.len()
    }

    fn extract_flow<'a>(packet: &'a SlicedPacket<'a>) -> Option<(FlowKey, &'a [u8])> {
        let (src_ip, dst_ip) = match &packet.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let h = ipv4.header();
                (
                    IpAddr::V4(h.source_addr()),
                    IpAddr::V4(h.destination_addr()),
                )
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                let h = ipv6.header();
                (
                    IpAddr::V6(h.source_addr()),
                    IpAddr::V6(h.destination_addr()),
                )
            }
            _ => return None,
        };

        match &packet.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let key = FlowKey::new(src_ip, tcp.source_port(), dst_ip, tcp.destination_port());
                Some((key, tcp.payload()))
            }
            Some(TransportSlice::Udp(udp)) => {
                let key = FlowKey::new(src_ip, udp.source_port(), dst_ip, udp.destination_port());
                Some((key, udp.payload()))
            }
            _ => None,
        }
    }

    fn try_classify(buf: &[u8]) -> Option<DpiContext> {
        CLASSIFIERS.iter().find_map(|f| f(buf))
    }
}

type Classifier = fn(&[u8]) -> Option<DpiContext>;

// Tablica klasyfikatorów wywoływanych kolejno aż do pierwszego dopasowania.
const CLASSIFIERS: &[Classifier] = &[
    classify_tls,
    classify_http,
    classify_ssh,
    classify_dns,
    classify_ftp,
    classify_smtp,
    classify_smb,
    classify_rdp,
    classify_quic,
];

// TLS: parsing ClientHello (SNI, ECH, wersja), fallback na wzorzec nagłówka.
fn classify_tls(buf: &[u8]) -> Option<DpiContext> {
    if buf.len() < 3 || buf[0] != 0x16 || buf[1] != 0x03 || !(1..=4).contains(&buf[2]) {
        return None;
    }

    if let Some(result) = tls::parse_tls_client_hello(buf) {
        return Some(tls::tls_to_dpi_context(&result));
    }

    if buf.len() >= 5 {
        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() >= 5 + record_len {
            return Some(DpiContext { app_proto: Some(AppProto::Tls), ..Default::default() });
        }
    }

    None
}

// HTTP: parsowanie nagłówków HTTP/1.1, rozpoznanie HTTP/2 preface.
fn classify_http(buf: &[u8]) -> Option<DpiContext> {
    http::parse_http(buf).map(|r| http::http_to_dpi_context(&r))
}

// SSH: parsowanie banneru wersji.
fn classify_ssh(buf: &[u8]) -> Option<DpiContext> {
    if buf.len() < 4 || !buf.starts_with(b"SSH-") {
        return None;
    }
    match ssh::parse_ssh(buf) {
        Some(result) => Some(ssh::ssh_to_dpi_context(&result)),
        None => Some(DpiContext { app_proto: Some(AppProto::Ssh), ..Default::default() }),
    }
}

// DNS: parsowanie nagłówka, QNAME, QTYPE i kierunku (query/response).
fn classify_dns(buf: &[u8]) -> Option<DpiContext> {
    dns::parse_dns(buf).map(|r| dns::dns_to_dpi_context(&r))
}

// FTP: banner serwera „220" lub komendy klienta.
fn classify_ftp(buf: &[u8]) -> Option<DpiContext> {
    const PREFIXES: &[&[u8]] = &[b"220 ", b"220-", b"USER", b"PASS", b"RETR", b"STOR"];
    (buf.len() >= 4 && PREFIXES.iter().any(|p| buf.starts_with(p)))
        .then(|| DpiContext { app_proto: Some(AppProto::Ftp), ..Default::default() })
}

// SMTP: komendy EHLO/HELO/MAIL na początku sesji.
fn classify_smtp(buf: &[u8]) -> Option<DpiContext> {
    const PREFIXES: &[&[u8]] = &[b"EHLO", b"HELO", b"MAIL"];
    (buf.len() >= 4 && PREFIXES.iter().any(|p| buf.starts_with(p)))
        .then(|| DpiContext { app_proto: Some(AppProto::Smtp), ..Default::default() })
}

// SMB: nagłówek NetBIOS Session + magic „\xFFSMB" (v1) lub „\xFESMB" (v2).
fn classify_smb(buf: &[u8]) -> Option<DpiContext> {
    (buf.len() >= 8 && buf[0] == 0x00 && (&buf[4..8] == b"\xFFSMB" || &buf[4..8] == b"\xFESMB"))
        .then(|| DpiContext { app_proto: Some(AppProto::Smb), ..Default::default() })
}

// RDP: nagłówek TPKT (wersja 3) z walidacją długości.
fn classify_rdp(buf: &[u8]) -> Option<DpiContext> {
    if buf.len() < 4 || buf[0] != 0x03 || buf[1] != 0x00 {
        return None;
    }
    let length = u16::from_be_bytes([buf[2], buf[3]]);
    (length >= 7 && (length as usize) <= buf.len() + 100)
        .then(|| DpiContext { app_proto: Some(AppProto::Rdp), ..Default::default() })
}

// QUIC: Long Header (bit 7) + znana wersja (v1, v2, negocjacja).
fn classify_quic(buf: &[u8]) -> Option<DpiContext> {
    if buf.len() < 5 || (buf[0] & 0x80) == 0 {
        return None;
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    (version == 0x00000001 || version == 0x6B3343CF || (version & 0x0F0F0F0F) == 0x0a0a0a0a)
        .then(|| DpiContext { app_proto: Some(AppProto::Quic), ..Default::default() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_entry_limits() {
        let mut entry = DpiSessionEntry::new();
        assert!(entry.result.is_none());
        assert!(!entry.limits_exceeded());

        for _ in 0..MAX_INSPECT_PACKETS {
            entry.append_payload(&[0x00; 100]);
        }
        assert!(entry.limits_exceeded());
    }

    #[test]
    fn test_session_entry_byte_limit() {
        let mut entry = DpiSessionEntry::new();
        let chunk = vec![0xAA; 8192];
        entry.append_payload(&chunk);
        entry.append_payload(&chunk);
        assert_eq!(entry.buffer.len(), MAX_INSPECT_BYTES);
        assert!(entry.limits_exceeded());
    }

    #[test]
    fn test_classify_tls() {
        let buf = [0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        let result = DpiClassifier::try_classify(&buf);
        assert!(result.is_some());
        assert_eq!(result.unwrap().app_proto, Some(AppProto::Tls));
    }

    #[test]
    fn test_classify_http_get() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = DpiClassifier::try_classify(buf);
        assert!(result.is_some());
        assert_eq!(result.unwrap().app_proto, Some(AppProto::Http));
    }

    #[test]
    fn test_classify_http_post() {
        let buf = b"POST /api/data HTTP/1.1\r\n";
        let result = DpiClassifier::try_classify(buf);
        assert!(result.is_some());
        assert_eq!(result.unwrap().app_proto, Some(AppProto::Http));
    }

    #[test]
    fn test_classify_ssh() {
        let buf = b"SSH-2.0-OpenSSH_8.9\r\n";
        let result = DpiClassifier::try_classify(buf);
        assert!(result.is_some());
        let ctx = result.unwrap();
        assert_eq!(ctx.app_proto, Some(AppProto::Ssh));
        assert_eq!(ctx.ssh_proto_version.as_deref(), Some("2.0"));
        assert_eq!(ctx.ssh_software.as_deref(), Some("OpenSSH_8.9"));
    }

    #[test]
    fn test_classify_dns() {
        // Pełny pakiet DNS query: example.com, QTYPE=A
        let buf = [
            0x12, 0x34,       // Transaction ID
            0x01, 0x00,       // Flags: query, RD=1
            0x00, 0x01,       // QDCOUNT=1
            0x00, 0x00,       // ANCOUNT=0
            0x00, 0x00,       // NSCOUNT=0
            0x00, 0x00,       // ARCOUNT=0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,             // koniec QNAME
            0x00, 0x01,       // QTYPE=A
            0x00, 0x01,       // QCLASS=IN
        ];
        let result = DpiClassifier::try_classify(&buf);
        assert!(result.is_some());
        let ctx = result.unwrap();
        assert_eq!(ctx.app_proto, Some(AppProto::Dns));
        assert_eq!(ctx.dns_query_name.as_deref(), Some("example.com"));
        assert_eq!(ctx.dns_query_type, Some(1));
        assert_eq!(ctx.dns_is_response, Some(false));
    }

    #[test]
    fn test_classify_ftp_banner() {
        let buf = b"220 Welcome to FTP server\r\n";
        let result = DpiClassifier::try_classify(buf);
        assert!(result.is_some());
        assert_eq!(result.unwrap().app_proto, Some(AppProto::Ftp));
    }

    #[test]
    fn test_classify_smtp() {
        let buf = b"EHLO mail.example.com\r\n";
        let result = DpiClassifier::try_classify(buf);
        assert!(result.is_some());
        assert_eq!(result.unwrap().app_proto, Some(AppProto::Smtp));
    }

    #[test]
    fn test_classify_smb() {
        let buf = [0x00, 0x00, 0x00, 0x45, 0xFE, 0x53, 0x4D, 0x42, 0x00, 0x00];
        let result = DpiClassifier::try_classify(&buf);
        assert!(result.is_some());
        assert_eq!(result.unwrap().app_proto, Some(AppProto::Smb));
    }

    #[test]
    fn test_classify_rdp() {
        let buf = [0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00];
        let result = DpiClassifier::try_classify(&buf);
        assert!(result.is_some());
        assert_eq!(result.unwrap().app_proto, Some(AppProto::Rdp));
    }

    #[test]
    fn test_classify_quic_v1() {
        let buf = [0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00];
        let result = DpiClassifier::try_classify(&buf);
        assert!(result.is_some());
        assert_eq!(result.unwrap().app_proto, Some(AppProto::Quic));
    }

    #[test]
    fn test_classify_unknown_data() {
        let buf = [0xDE, 0xAD, 0xBE, 0xEF];
        let result = DpiClassifier::try_classify(&buf);
        assert!(result.is_none());
    }

    #[test]
    fn test_classify_empty() {
        let result = DpiClassifier::try_classify(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_flow_key_bidirectional() {
        let k1 = FlowKey::new(
            "10.0.0.1".parse().unwrap(), 12345,
            "10.0.0.2".parse().unwrap(), 443,
        );
        let k2 = FlowKey::new(
            "10.0.0.2".parse().unwrap(), 443,
            "10.0.0.1".parse().unwrap(), 12345,
        );
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_classifier_session_lifecycle() {
        let classifier = DpiClassifier::new();
        assert_eq!(classifier.session_count(), 0);

        let key = FlowKey::new(
            "10.0.0.1".parse().unwrap(), 50000,
            "10.0.0.2".parse().unwrap(), 443,
        );

        classifier.sessions.insert(key.clone(), DpiSessionEntry::new());
        assert_eq!(classifier.session_count(), 1);

        classifier.remove_session(
            "10.0.0.1".parse().unwrap(), 50000,
            "10.0.0.2".parse().unwrap(), 443,
        );
        assert_eq!(classifier.session_count(), 0);
    }

    #[test]
    fn test_classifier_caches_result() {
        let classifier = DpiClassifier::new();
        let key = FlowKey::new(
            "10.0.0.1".parse().unwrap(), 50000,
            "10.0.0.2".parse().unwrap(), 443,
        );

        let mut entry = DpiSessionEntry::new();
        // Pełny rekord TLS (5B nagłówek + 5B payload) — fallback na bazowe rozpoznanie.
        entry.append_payload(&[0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]);
        let ctx = DpiClassifier::try_classify(&entry.buffer).unwrap();
        entry.result = Some(ctx.clone());
        classifier.sessions.insert(key.clone(), entry);

        let cached = classifier.sessions.get(&key).unwrap();
        assert!(cached.result.is_some());
        assert_eq!(cached.result.as_ref().unwrap().app_proto, Some(AppProto::Tls));
    }

    #[test]
    fn test_unknown_after_packet_limit() {
        let mut entry = DpiSessionEntry::new();
        for _ in 0..MAX_INSPECT_PACKETS {
            entry.append_payload(&[0xDE, 0xAD, 0xBE, 0xEF]);
        }
        assert!(entry.limits_exceeded());
        assert!(DpiClassifier::try_classify(&entry.buffer).is_none());
    }
}
