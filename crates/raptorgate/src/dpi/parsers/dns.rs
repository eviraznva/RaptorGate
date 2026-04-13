use simple_dns::{Packet, PacketFlag};

use crate::dpi::AppProto;
use crate::dpi::context::DpiContext;

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
    Opt,
    Srv,
    Ds,
    Rrsig,
    Nsec,
    Dnskey,
    Nsec3,
    Nsec3Param,
    Cds,
    Cdnskey,
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
            41 => Self::Opt,
            33 => Self::Srv,
            43 => Self::Ds,
            46 => Self::Rrsig,
            47 => Self::Nsec,
            48 => Self::Dnskey,
            50 => Self::Nsec3,
            51 => Self::Nsec3Param,
            59 => Self::Cds,
            60 => Self::Cdnskey,
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
            DnsRecordType::Opt => 41,
            DnsRecordType::Srv => 33,
            DnsRecordType::Ds => 43,
            DnsRecordType::Rrsig => 46,
            DnsRecordType::Nsec => 47,
            DnsRecordType::Dnskey => 48,
            DnsRecordType::Nsec3 => 50,
            DnsRecordType::Nsec3Param => 51,
            DnsRecordType::Cds => 59,
            DnsRecordType::Cdnskey => 60,
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
    pub authority_count: u16,
    pub authority_types: Vec<DnsRecordType>,
    pub additional_count: u16,
    pub additional_types: Vec<DnsRecordType>,
    pub has_opt: bool,
    pub dnssec_ok: bool,
    pub authentic_data: bool,
    pub checking_disabled: bool,
    pub rcode: u16,
    pub has_dnssec_records: bool,
    pub response_size: u16,
}

// Parsuje pakiet DNS i wyodrębnia nazwę domeny, typ zapytania oraz kierunek.
pub fn parse_dns(buf: &[u8]) -> Option<DnsParseResult> {
    let packet = Packet::parse(buf).ok()?;
    let is_response = packet.has_flags(PacketFlag::RESPONSE);
    let authentic_data = packet.has_flags(PacketFlag::AUTHENTIC_DATA);
    let checking_disabled = packet.has_flags(PacketFlag::CHECKING_DISABLED);
    let question = packet.questions.first()?;

    let answer_count = packet.answers.len() as u16;
    let answer_types = collect_record_types(&packet.answers);
    let authority_count = packet.name_servers.len() as u16;
    let authority_types = collect_record_types(&packet.name_servers);
    let has_opt = packet.opt().is_some();
    let dnssec_ok = if has_opt {
        extract_dnssec_ok_bit(buf)?
    } else {
        false
    };
    let mut additional_types = Vec::with_capacity(packet.additional_records.len() + usize::from(has_opt));
    if has_opt {
        additional_types.push(DnsRecordType::Opt);
    }
    additional_types.extend(collect_record_types(&packet.additional_records));
    let additional_count = additional_types.len() as u16;
    let has_dnssec_records = answer_types
        .iter()
        .chain(authority_types.iter())
        .chain(additional_types.iter())
        .any(|record_type| record_type.is_dnssec());

    Some(DnsParseResult {
        is_response,
        query_name: Some(question.qname.to_string()),
        query_type: Some(DnsRecordType::from(u16::from(question.qtype))),
        answer_count,
        answer_types,
        authority_count,
        authority_types,
        additional_count,
        additional_types,
        has_opt,
        dnssec_ok,
        authentic_data,
        checking_disabled,
        rcode: rcode_to_u16(packet.rcode()),
        has_dnssec_records,
        response_size: buf.len() as u16,
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
        ..Default::default()
    }
}

fn collect_record_types(records: &[simple_dns::ResourceRecord<'_>]) -> Vec<DnsRecordType> {
    records
        .iter()
        .map(|rr| DnsRecordType::from(u16::from(rr.rdata.type_code())))
        .collect()
}

fn rcode_to_u16(rcode: simple_dns::RCODE) -> u16 {
    match rcode {
        simple_dns::RCODE::NoError => 0,
        simple_dns::RCODE::FormatError => 1,
        simple_dns::RCODE::ServerFailure => 2,
        simple_dns::RCODE::NameError => 3,
        simple_dns::RCODE::NotImplemented => 4,
        simple_dns::RCODE::Refused => 5,
        simple_dns::RCODE::YXDOMAIN => 6,
        simple_dns::RCODE::YXRRSET => 7,
        simple_dns::RCODE::NXRRSET => 8,
        simple_dns::RCODE::NOTAUTH => 9,
        simple_dns::RCODE::NOTZONE => 10,
        simple_dns::RCODE::BADVERS => 16,
        simple_dns::RCODE::Reserved => 0xffff,
    }
}

fn extract_dnssec_ok_bit(buf: &[u8]) -> Option<bool> {
    if buf.len() < 12 {
        return None;
    }

    let question_count = read_u16(buf, 4)? as usize;
    let answer_count = read_u16(buf, 6)? as usize;
    let authority_count = read_u16(buf, 8)? as usize;
    let additional_count = read_u16(buf, 10)? as usize;

    let mut offset = 12usize;
    offset = skip_questions(buf, offset, question_count)?;
    offset = skip_resource_records(buf, offset, answer_count)?;
    offset = skip_resource_records(buf, offset, authority_count)?;

    for _ in 0..additional_count {
        let name_len = skip_name(buf, offset)?;
        let rr_offset = offset + name_len;
        let rr_type = read_u16(buf, rr_offset)?;
        let ttl = read_u32(buf, rr_offset + 4)?;
        let rdlength = read_u16(buf, rr_offset + 8)? as usize;

        if rr_type == 41 {
            return Some(ttl & 0x8000 != 0);
        }

        offset = rr_offset.checked_add(10)?.checked_add(rdlength)?;
        if offset > buf.len() {
            return None;
        }
    }

    Some(false)
}

fn skip_questions(buf: &[u8], mut offset: usize, count: usize) -> Option<usize> {
    for _ in 0..count {
        offset = offset.checked_add(skip_name(buf, offset)?)?;
        offset = offset.checked_add(4)?;
        if offset > buf.len() {
            return None;
        }
    }
    Some(offset)
}

fn skip_resource_records(buf: &[u8], mut offset: usize, count: usize) -> Option<usize> {
    for _ in 0..count {
        let name_len = skip_name(buf, offset)?;
        let rr_offset = offset.checked_add(name_len)?;
        let rdlength = read_u16(buf, rr_offset + 8)? as usize;
        offset = rr_offset.checked_add(10)?.checked_add(rdlength)?;
        if offset > buf.len() {
            return None;
        }
    }
    Some(offset)
}

fn skip_name(buf: &[u8], offset: usize) -> Option<usize> {
    let mut cursor = offset;
    loop {
        let len = *buf.get(cursor)?;
        if len & 0b1100_0000 == 0b1100_0000 {
            buf.get(cursor + 1)?;
            return Some(cursor + 2 - offset);
        }
        if len == 0 {
            return Some(cursor + 1 - offset);
        }
        cursor = cursor.checked_add(1 + len as usize)?;
        if cursor > buf.len() {
            return None;
        }
    }
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = buf.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

impl DnsRecordType {
    fn is_dnssec(self) -> bool {
        matches!(
            self,
            Self::Ds
                | Self::Rrsig
                | Self::Nsec
                | Self::Dnskey
                | Self::Nsec3
                | Self::Nsec3Param
                | Self::Cds
                | Self::Cdnskey
        )
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
        build_dns_message_with_sections(domain_labels, qtype, answers, &[], &[], [0x81, 0x80], None)
    }

    fn build_dns_message_with_sections(
        domain_labels: &[&str],
        qtype: u16,
        answers: &[(u16, &[u8])],
        authority: &[(u16, &[u8])],
        additional: &[(u16, &[u8])],
        flags: [u8; 2],
        opt: Option<(u16, u32, &[(u16, &[u8])])>,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0xAB, 0xCD]); // Transaction ID
        pkt.extend_from_slice(&flags);
        pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&(authority.len() as u16).to_be_bytes()); // NSCOUNT
        let additional_count = additional.len() as u16 + u16::from(opt.is_some());
        pkt.extend_from_slice(&additional_count.to_be_bytes()); // ARCOUNT

        let name_bytes = encode_name(domain_labels);
        pkt.extend_from_slice(&name_bytes);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

        append_records(&mut pkt, &name_bytes, answers);
        append_records(&mut pkt, &name_bytes, authority);
        append_records(&mut pkt, &name_bytes, additional);

        if let Some((udp_size, ttl, opt_codes)) = opt {
            append_opt_record(&mut pkt, udp_size, ttl, opt_codes);
        }

        pkt
    }

    fn append_records(pkt: &mut Vec<u8>, name_bytes: &[u8], records: &[(u16, &[u8])]) {
        for (rtype, rdata) in records {
            pkt.extend_from_slice(&name_bytes); // NAME
            pkt.extend_from_slice(&rtype.to_be_bytes()); // TYPE
            pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
            pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
            pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
            pkt.extend_from_slice(rdata); // RDATA
        }
    }

    fn append_opt_record(
        pkt: &mut Vec<u8>,
        udp_packet_size: u16,
        ttl: u32,
        opt_codes: &[(u16, &[u8])],
    ) {
        let mut rdata_len = 0u16;
        for (_, data) in opt_codes {
            rdata_len += 4 + data.len() as u16;
        }

        pkt.push(0x00); // root name
        pkt.extend_from_slice(&41u16.to_be_bytes()); // TYPE=OPT
        pkt.extend_from_slice(&udp_packet_size.to_be_bytes()); // CLASS=requestor UDP size
        pkt.extend_from_slice(&ttl.to_be_bytes());
        pkt.extend_from_slice(&rdata_len.to_be_bytes());

        for (code, data) in opt_codes {
            pkt.extend_from_slice(&code.to_be_bytes());
            pkt.extend_from_slice(&(data.len() as u16).to_be_bytes());
            pkt.extend_from_slice(data);
        }
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
        assert_eq!(result.authority_count, 0);
        assert!(result.authority_types.is_empty());
        assert_eq!(result.additional_count, 0);
        assert!(result.additional_types.is_empty());
        assert!(!result.has_opt);
        assert!(!result.dnssec_ok);
        assert!(!result.authentic_data);
        assert!(!result.checking_disabled);
        assert_eq!(result.rcode, 0);
        assert!(!result.has_dnssec_records);
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
    fn dnssec_record_type_mappings_cover_query_types() {
        let cases = [
            (43, DnsRecordType::Ds),
            (46, DnsRecordType::Rrsig),
            (47, DnsRecordType::Nsec),
            (48, DnsRecordType::Dnskey),
            (50, DnsRecordType::Nsec3),
            (51, DnsRecordType::Nsec3Param),
            (59, DnsRecordType::Cds),
            (60, DnsRecordType::Cdnskey),
        ];

        for (qtype, expected) in cases {
            assert_eq!(DnsRecordType::from(qtype), expected);
            assert_eq!(u16::from(expected), qtype);
        }
    }

    #[test]
    fn opt_record_type_roundtrip() {
        assert_eq!(DnsRecordType::from(41), DnsRecordType::Opt);
        assert_eq!(u16::from(DnsRecordType::Opt), 41);
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
        assert_eq!(
            result.answer_types,
            vec![DnsRecordType::A, DnsRecordType::A]
        );
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
        assert_eq!(
            result.answer_types,
            vec![DnsRecordType::Cname, DnsRecordType::A]
        );
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
    fn dnssec_record_types_roundtrip() {
        let cases: &[(u16, DnsRecordType)] = &[
            (43, DnsRecordType::Ds),
            (46, DnsRecordType::Rrsig),
            (47, DnsRecordType::Nsec),
            (48, DnsRecordType::Dnskey),
            (50, DnsRecordType::Nsec3),
            (51, DnsRecordType::Nsec3Param),
            (59, DnsRecordType::Cds),
            (60, DnsRecordType::Cdnskey),
        ];

        for (rtype, expected) in cases {
            assert_eq!(DnsRecordType::from(*rtype), *expected);
            assert_eq!(u16::from(*expected), *rtype);
        }
    }

    #[test]
    fn unknown_record_type_stays_other() {
        assert_eq!(DnsRecordType::from(65280), DnsRecordType::Other(65280));
        assert_eq!(u16::from(DnsRecordType::Other(65280)), 65280);
    }

    #[test]
    fn response_collects_authority_additional_and_dnssec_metadata() {
        let ds_rdata: &[u8] = &[0x12, 0x34, 0x08, 0x02, 0xde, 0xad, 0xbe, 0xef];
        let a_rdata: &[u8] = &[1, 1, 1, 1];
        let pkt = build_dns_message_with_sections(
            &["secure", "example", "com"],
            1,
            &[(48, &[0x01, 0x00, 0x03, 0x08, 0xaa, 0xbb, 0xcc, 0xdd])],
            &[(43, ds_rdata)],
            &[(1, a_rdata)],
            [0x81, 0xb0],
            Some((1232, 0, &[])),
        );

        let result = parse_dns(&pkt).unwrap();

        assert_eq!(result.answer_count, 1);
        assert_eq!(result.answer_types, vec![DnsRecordType::Dnskey]);
        assert_eq!(result.authority_count, 1);
        assert_eq!(result.authority_types, vec![DnsRecordType::Ds]);
        assert_eq!(result.additional_count, 2);
        assert_eq!(
            result.additional_types,
            vec![DnsRecordType::Opt, DnsRecordType::A]
        );
        assert!(result.has_opt);
        assert!(!result.dnssec_ok);
        assert!(result.authentic_data);
        assert!(result.checking_disabled);
        assert_eq!(result.rcode, 0);
        assert!(result.has_dnssec_records);
    }

    #[test]
    fn response_extracts_do_bit_from_opt_ttl() {
        let pkt = build_dns_message_with_sections(
            &["secure", "example", "com"],
            1,
            &[],
            &[],
            &[],
            [0x81, 0x80],
            Some((1232, 0x0000_8000, &[])),
        );

        let result = parse_dns(&pkt).unwrap();

        assert!(result.has_opt);
        assert!(result.dnssec_ok);
    }

    #[test]
    fn response_rcode_is_extracted() {
        let pkt = build_dns_message_with_sections(
            &["missing", "example", "com"],
            1,
            &[],
            &[],
            &[],
            [0x81, 0x83],
            None,
        );

        let result = parse_dns(&pkt).unwrap();

        assert_eq!(result.rcode, 3);
        assert!(!result.has_opt);
        assert!(!result.has_dnssec_records);
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
            authority_count: 0,
            authority_types: vec![],
            additional_count: 0,
            additional_types: vec![],
            has_opt: false,
            dnssec_ok: false,
            authentic_data: false,
            checking_disabled: false,
            rcode: 0,
            has_dnssec_records: false,
            response_size: 128,
        };
        let ctx = dns_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Dns));
        assert_eq!(ctx.dns_query_name.as_deref(), Some("example.com"));
        assert_eq!(ctx.dns_query_type, Some(DnsRecordType::A));
        assert_eq!(ctx.dns_is_response, Some(false));
        assert_eq!(ctx.dns_answer_count, 2);
        assert_eq!(
            ctx.dns_answer_types,
            vec![DnsRecordType::A, DnsRecordType::A]
        );
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
            authority_count: 0,
            authority_types: vec![],
            additional_count: 0,
            additional_types: vec![],
            has_opt: false,
            dnssec_ok: false,
            authentic_data: false,
            checking_disabled: false,
            rcode: 0,
            has_dnssec_records: false,
            response_size: 64,
        };
        let ctx = dns_to_dpi_context(&result);
        assert_eq!(ctx.dns_is_response, Some(true));
        assert_eq!(ctx.dns_query_type, Some(DnsRecordType::Aaaa));
        assert_eq!(ctx.dns_answer_count, 1);
        assert_eq!(ctx.dns_answer_types, vec![DnsRecordType::Aaaa]);
        assert_eq!(ctx.dns_response_size, 64);
    }
}
