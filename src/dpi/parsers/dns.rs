use simple_dns::{Packet, PacketFlag};

use crate::dpi::context::DpiContext;
use crate::dpi::AppProto;

// Typ rekordu DNS (QTYPE / RTYPE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    Ns,
    Cname,
    Soa,
    Null,
    Mx,
    Txt,
    Aaaa,
    Srv,
    Svcb,
    Https,
    Any,
    Other(u16),
}

impl From<u16> for DnsRecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            10 => Self::Null,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            64 => Self::Svcb,
            65 => Self::Https,
            255 => Self::Any,
            other => Self::Other(other),
        }
    }
}

impl From<DnsRecordType> for u16 {
    fn from(value: DnsRecordType) -> Self {
        match value {
            DnsRecordType::A => 1,
            DnsRecordType::Ns => 2,
            DnsRecordType::Cname => 5,
            DnsRecordType::Soa => 6,
            DnsRecordType::Null => 10,
            DnsRecordType::Mx => 15,
            DnsRecordType::Txt => 16,
            DnsRecordType::Aaaa => 28,
            DnsRecordType::Srv => 33,
            DnsRecordType::Svcb => 64,
            DnsRecordType::Https => 65,
            DnsRecordType::Any => 255,
            DnsRecordType::Other(v) => v,
        }
    }
}

// Wynik parsowania pakietu DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsParseResult {
    pub is_response: bool,
    pub query_name: Option<String>,
    pub query_type: Option<DnsRecordType>,
    pub answer_count: u16,
    pub answer_types: Vec<DnsRecordType>,
    pub response_size: u16,
    pub dns_has_ech_hints: bool,
}

// Parsuje pakiet DNS i wyodrębnia nazwę domeny, typ zapytania oraz kierunek.
pub fn parse_dns(buf: &[u8]) -> Option<DnsParseResult> {
    let packet = Packet::parse(buf).ok()?;
    let is_response = packet.has_flags(PacketFlag::RESPONSE);
    let question = packet.questions.first()?;

    let answer_count = packet.answers.len() as u16;
    let answer_types: Vec<DnsRecordType> = packet
        .answers
        .iter()
        .map(|rr| DnsRecordType::from(u16::from(rr.rdata.type_code())))
        .collect();

    let dns_has_ech_hints = is_response
        && answer_types.iter().any(|t| matches!(t, DnsRecordType::Https | DnsRecordType::Svcb));

    Some(DnsParseResult {
        is_response,
        query_name: Some(question.qname.to_string()),
        query_type: Some(DnsRecordType::from(u16::from(question.qtype))),
        answer_count,
        answer_types,
        response_size: buf.len() as u16,
        dns_has_ech_hints,
    })
}

// Konwertuje wynik parsowania DNS na DpiContext.
pub fn dns_to_dpi_context(result: &DnsParseResult) -> DpiContext {
    DpiContext {
        app_proto: Some(AppProto::Dns),
        dns_query_name: result.query_name.clone(),
        dns_query_type: result.query_type,
        dns_is_response: Some(result.is_response),
        dns_answer_count: result.answer_count,
        dns_answer_types: result.answer_types.clone(),
        dns_response_size: result.response_size,
        dns_has_ech_hints: result.dns_has_ech_hints,
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
        build_dns_response_with_answers(domain_labels, qtype, &[])
    }

    // Buduje odpowiedź DNS z rekordami w sekcji Answer.
    // Każda krotka: (typ rekordu, rdata).
    fn build_dns_response_with_answers(
        domain_labels: &[&str],
        qtype: u16,
        answers: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xAB, 0xCD]); // Transaction ID
        pkt.extend_from_slice(&[0x81, 0x80]); // Flags: response, RD=1, RA=1
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        let name_bytes = encode_name(domain_labels);
        pkt.extend_from_slice(&name_bytes);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

        for (rtype, rdata) in answers {
            pkt.extend_from_slice(&name_bytes); // NAME
            pkt.extend_from_slice(&rtype.to_be_bytes()); // TYPE
            pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
            pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
            pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
            pkt.extend_from_slice(rdata); // RDATA
        }
        pkt
    }

    #[test]
    fn query_a_record() {
        let pkt = build_dns_query(&["example", "com"], 1);
        let result = parse_dns(&pkt).unwrap();
        assert!(!result.is_response);
        assert_eq!(result.query_name.as_deref(), Some("example.com"));
        assert_eq!(result.query_type, Some(DnsRecordType::A));
        assert_eq!(result.answer_count, 0);
        assert!(result.answer_types.is_empty());
        assert_eq!(result.response_size, pkt.len() as u16);
    }

    #[test]
    fn query_aaaa_record() {
        let pkt = build_dns_query(&["ipv6", "example", "org"], 28);
        let result = parse_dns(&pkt).unwrap();
        assert!(!result.is_response);
        assert_eq!(result.query_name.as_deref(), Some("ipv6.example.org"));
        assert_eq!(result.query_type, Some(DnsRecordType::Aaaa));
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
        assert_eq!(result.query_type, Some(DnsRecordType::Mx));
    }

    #[test]
    fn txt_record_type() {
        let pkt = build_dns_query(&["example", "com"], 16);
        let result = parse_dns(&pkt).unwrap();
        assert_eq!(result.query_type, Some(DnsRecordType::Txt));
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
    fn response_with_a_record() {
        let ip: &[u8] = &[93, 184, 216, 34]; // 93.184.216.34
        let pkt = build_dns_response_with_answers(&["example", "com"], 1, &[(1, ip)]);
        let result = parse_dns(&pkt).unwrap();
        assert!(result.is_response);
        assert_eq!(result.answer_count, 1);
        assert_eq!(result.answer_types, vec![DnsRecordType::A]);
        assert_eq!(result.response_size, pkt.len() as u16);
    }

    #[test]
    fn response_with_txt_record() {
        let txt = b"\x0dhello tunnelx";
        let pkt = build_dns_response_with_answers(&["t", "suspect", "com"], 16, &[(16, txt)]);
        let result = parse_dns(&pkt).unwrap();
        assert_eq!(result.answer_count, 1);
        assert_eq!(result.answer_types, vec![DnsRecordType::Txt]);
    }

    #[test]
    fn response_with_multiple_answers() {
        let ip1: &[u8] = &[1, 2, 3, 4];
        let ip2: &[u8] = &[5, 6, 7, 8];
        let pkt =
            build_dns_response_with_answers(&["cdn", "example", "com"], 1, &[(1, ip1), (1, ip2)]);
        let result = parse_dns(&pkt).unwrap();
        assert_eq!(result.answer_count, 2);
        assert_eq!(result.answer_types, vec![DnsRecordType::A, DnsRecordType::A]);
    }

    #[test]
    fn response_with_cname_and_a() {
        let cname_rdata = encode_name(&["real", "example", "com"]);
        let a_rdata: &[u8] = &[10, 0, 0, 1];
        let pkt = build_dns_response_with_answers(
            &["alias", "example", "com"],
            1,
            &[(5, &cname_rdata), (1, a_rdata)],
        );
        let result = parse_dns(&pkt).unwrap();
        assert_eq!(result.answer_count, 2);
        assert_eq!(result.answer_types, vec![DnsRecordType::Cname, DnsRecordType::A]);
    }

    #[test]
    fn response_with_null_record() {
        let null_data: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let pkt =
            build_dns_response_with_answers(&["tun", "suspect", "com"], 10, &[(10, null_data)]);
        let result = parse_dns(&pkt).unwrap();
        assert_eq!(result.answer_count, 1);
        assert_eq!(result.answer_types, vec![DnsRecordType::Null]);
    }

    #[test]
    fn response_size_grows_with_answers() {
        let query = build_dns_query(&["example", "com"], 1);
        let response_empty = build_dns_response(&["example", "com"], 1);
        let response_with =
            build_dns_response_with_answers(&["example", "com"], 1, &[(1, &[1, 2, 3, 4])]);

        let q = parse_dns(&query).unwrap();
        let r_empty = parse_dns(&response_empty).unwrap();
        let r_with = parse_dns(&response_with).unwrap();

        assert!(r_with.response_size > r_empty.response_size);
        assert!(r_empty.response_size > 0);
        assert!(q.response_size > 0);
    }

    #[test]
    fn to_dpi_context_maps_fields() {
        let result = DnsParseResult {
            is_response: false,
            query_name: Some("example.com".into()),
            query_type: Some(DnsRecordType::A),
            answer_count: 2,
            answer_types: vec![DnsRecordType::A, DnsRecordType::A],
            response_size: 128,
            dns_has_ech_hints: false,
        };
        let ctx = dns_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Dns));
        assert_eq!(ctx.dns_query_name.as_deref(), Some("example.com"));
        assert_eq!(ctx.dns_query_type, Some(DnsRecordType::A));
        assert_eq!(ctx.dns_is_response, Some(false));
        assert_eq!(ctx.dns_answer_count, 2);
        assert_eq!(ctx.dns_answer_types, vec![DnsRecordType::A, DnsRecordType::A]);
        assert_eq!(ctx.dns_response_size, 128);
    }

    #[test]
    fn to_dpi_context_response() {
        let result = DnsParseResult {
            is_response: true,
            query_name: Some("test.org".into()),
            query_type: Some(DnsRecordType::Aaaa),
            answer_count: 1,
            answer_types: vec![DnsRecordType::Aaaa],
            response_size: 64,
            dns_has_ech_hints: false,
        };
        let ctx = dns_to_dpi_context(&result);
        assert_eq!(ctx.dns_is_response, Some(true));
        assert_eq!(ctx.dns_query_type, Some(DnsRecordType::Aaaa));
        assert_eq!(ctx.dns_answer_count, 1);
        assert_eq!(ctx.dns_answer_types, vec![DnsRecordType::Aaaa]);
        assert_eq!(ctx.dns_response_size, 64);
    }

    #[test]
    fn response_with_https_record() {
        let rdata: &[u8] = &[0x00, 0x01, 0x00];
        let pkt = build_dns_response_with_answers(&["example", "com"], 65, &[(65, rdata)]);
        let result = parse_dns(&pkt).unwrap();
        assert!(result.is_response);
        assert_eq!(result.answer_count, 1);
        assert_eq!(result.answer_types, vec![DnsRecordType::Https]);
        assert!(result.dns_has_ech_hints);
    }

    #[test]
    fn response_with_svcb_record() {
        let rdata: &[u8] = &[0x00, 0x01, 0x00];
        let pkt = build_dns_response_with_answers(&["example", "com"], 64, &[(64, rdata)]);
        let result = parse_dns(&pkt).unwrap();
        assert_eq!(result.answer_types, vec![DnsRecordType::Svcb]);
        assert!(result.dns_has_ech_hints);
    }

    #[test]
    fn query_https_no_ech_flag() {
        let pkt = build_dns_query(&["example", "com"], 65);
        let result = parse_dns(&pkt).unwrap();
        assert!(!result.is_response);
        assert_eq!(result.query_type, Some(DnsRecordType::Https));
        assert!(!result.dns_has_ech_hints);
    }

    #[test]
    fn response_a_record_no_ech() {
        let ip: &[u8] = &[1, 2, 3, 4];
        let pkt = build_dns_response_with_answers(&["example", "com"], 1, &[(1, ip)]);
        let result = parse_dns(&pkt).unwrap();
        assert!(!result.dns_has_ech_hints);
    }

    #[test]
    fn to_dpi_context_maps_ech_hints() {
        let result = DnsParseResult {
            is_response: true,
            query_name: Some("example.com".into()),
            query_type: Some(DnsRecordType::Https),
            answer_count: 1,
            answer_types: vec![DnsRecordType::Https],
            response_size: 64,
            dns_has_ech_hints: true,
        };
        let ctx = dns_to_dpi_context(&result);
        assert!(ctx.dns_has_ech_hints);
    }
}
