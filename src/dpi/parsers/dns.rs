use simple_dns::{Packet, PacketFlag};

use crate::dpi::context::DpiContext;
use crate::dpi::AppProto;

// Wynik parsowania pakietu DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsParseResult {
    pub is_response: bool,
    pub query_name: Option<String>,
    pub query_type: Option<u16>,
}

// Parsuje pakiet DNS i wyodrębnia nazwę domeny, typ zapytania oraz kierunek.
pub fn parse_dns(buf: &[u8]) -> Option<DnsParseResult> {
    let packet = Packet::parse(buf).ok()?;
    let is_response = packet.has_flags(PacketFlag::RESPONSE);
    let question = packet.questions.first()?;

    Some(DnsParseResult {
        is_response,
        query_name: Some(question.qname.to_string()),
        query_type: Some(question.qtype.into()),
    })
}

// Konwertuje wynik parsowania DNS na DpiContext.
pub fn dns_to_dpi_context(result: &DnsParseResult) -> DpiContext {
    DpiContext {
        app_proto: Some(AppProto::Dns),
        dns_query_name: result.query_name.clone(),
        dns_query_type: result.query_type,
        dns_is_response: Some(result.is_response),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0x00);
        out
    }

    fn build_dns_query(domain_labels: &[&str], qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xAB, 0xCD]); // Transaction ID
        pkt.extend_from_slice(&[0x01, 0x00]); // Flags: query, RD=1
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
        pkt.extend_from_slice(&encode_name(domain_labels));
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        pkt
    }

    fn build_dns_response(domain_labels: &[&str], qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xAB, 0xCD]); // Transaction ID
        pkt.extend_from_slice(&[0x81, 0x80]); // Flags: response, RD=1, RA=1
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
        pkt.extend_from_slice(&encode_name(domain_labels));
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        pkt
    }

    #[test]
    fn query_a_record() {
        let pkt = build_dns_query(&["example", "com"], 1);
        let result = parse_dns(&pkt).unwrap();
        assert!(!result.is_response);
        assert_eq!(result.query_name.as_deref(), Some("example.com"));
        assert_eq!(result.query_type, Some(1));
    }

    #[test]
    fn query_aaaa_record() {
        let pkt = build_dns_query(&["ipv6", "example", "org"], 28);
        let result = parse_dns(&pkt).unwrap();
        assert!(!result.is_response);
        assert_eq!(result.query_name.as_deref(), Some("ipv6.example.org"));
        assert_eq!(result.query_type, Some(28));
    }

    #[test]
    fn response_detected() {
        let pkt = build_dns_response(&["example", "com"], 1);
        let result = parse_dns(&pkt).unwrap();
        assert!(result.is_response);
        assert_eq!(result.query_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn single_label() {
        let pkt = build_dns_query(&["localhost"], 1);
        let result = parse_dns(&pkt).unwrap();
        assert_eq!(result.query_name.as_deref(), Some("localhost"));
    }

    #[test]
    fn deep_subdomain() {
        let pkt = build_dns_query(&["a", "b", "c", "d", "example", "com"], 1);
        let result = parse_dns(&pkt).unwrap();
        assert_eq!(result.query_name.as_deref(), Some("a.b.c.d.example.com"));
    }

    #[test]
    fn mx_record_type() {
        let pkt = build_dns_query(&["example", "com"], 15);
        let result = parse_dns(&pkt).unwrap();
        assert_eq!(result.query_type, Some(15));
    }

    #[test]
    fn txt_record_type() {
        let pkt = build_dns_query(&["example", "com"], 16);
        let result = parse_dns(&pkt).unwrap();
        assert_eq!(result.query_type, Some(16));
    }

    #[test]
    fn pointer_compression() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00, 0x01]); // ID
        pkt.extend_from_slice(&[0x81, 0x80]); // Flags: response
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        pkt.extend_from_slice(&encode_name(&["example", "com"]));
        pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

        let result = parse_dns(&pkt).unwrap();
        assert!(result.is_response);
        assert_eq!(result.query_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn too_short_for_header() {
        let pkt = [0x00; 11];
        assert!(parse_dns(&pkt).is_none());
    }

    #[test]
    fn truncated_qname() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00, 0x01]); // ID
        pkt.extend_from_slice(&[0x01, 0x00]); // Flags
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        pkt.push(0x07); // etykieta 7 bajtów, ale brak danych
        assert!(parse_dns(&pkt).is_none());
    }

    #[test]
    fn pointer_out_of_bounds() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00, 0x01, 0x01, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&[0xC0, 0xFF]);
        assert!(parse_dns(&pkt).is_none());
    }

    #[test]
    fn to_dpi_context_maps_fields() {
        let result = DnsParseResult {
            is_response: false,
            query_name: Some("example.com".into()),
            query_type: Some(1),
        };
        let ctx = dns_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Dns));
        assert_eq!(ctx.dns_query_name.as_deref(), Some("example.com"));
        assert_eq!(ctx.dns_query_type, Some(1));
        assert_eq!(ctx.dns_is_response, Some(false));
    }

    #[test]
    fn to_dpi_context_response() {
        let result = DnsParseResult {
            is_response: true,
            query_name: Some("test.org".into()),
            query_type: Some(28),
        };
        let ctx = dns_to_dpi_context(&result);
        assert_eq!(ctx.dns_is_response, Some(true));
        assert_eq!(ctx.dns_query_type, Some(28));
    }
}
