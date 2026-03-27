use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_plaintext, SNIType, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};

use crate::dpi::context::DpiContext;
use crate::dpi::AppProto;

const EXT_ECH: u16 = 0xfe0d;

// Wynik parsowania TLS ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsParseResult {
    pub sni: Option<String>,
    pub version: u16,
    pub ech_detected: bool,
}

// Parsuje TLS ClientHello i wyodrębnia SNI, wersję i obecność ECH.
pub fn parse_tls_client_hello(buf: &[u8]) -> Option<TlsParseResult> {
    let (_, plaintext) = parse_tls_plaintext(buf).ok()?;

    let msg = plaintext.msg.first()?;
    let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg else {
        return None;
    };

    let mut sni = None;
    let mut ech_detected = false;
    let mut version = ch.version.0;

    if let Some(ext_data) = ch.ext {
        let (_, extensions) = parse_tls_client_hello_extensions(ext_data).ok()?;

        for ext in &extensions {
            match ext {
                TlsExtension::SNI(entries) => {
                    sni = entries.iter().find_map(|(sni_type, data)| {
                        (*sni_type == SNIType::HostName)
                            .then(|| std::str::from_utf8(data).ok())
                            .flatten()
                            .map(|s| s.to_lowercase())
                    });
                }
                TlsExtension::SupportedVersions(versions) => {
                    if let Some(v) = versions
                        .iter()
                        .map(|v| v.0)
                        .filter(|v| (v & 0x0f0f) != 0x0a0a)
                        .max()
                    {
                        version = v;
                    }
                }
                TlsExtension::Unknown(ext_type, _) if ext_type.0 == EXT_ECH => {
                    ech_detected = true;
                }
                _ => {}
            }
        }
    }

    Some(TlsParseResult {
        sni,
        version,
        ech_detected,
    })
}

// Konwertuje wynik parsowania TLS na DpiContext.
pub fn tls_to_dpi_context(result: &TlsParseResult) -> DpiContext {
    DpiContext {
        app_proto: Some(AppProto::Tls),
        tls_sni: result.sni.clone(),
        tls_version: Some(result.version),
        tls_ech_detected: result.ech_detected,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
    const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
    const SNI_HOST_NAME: u8 = 0x00;

    // Helper: buduje minimalny TLS ClientHello z podanymi rozszerzeniami.
    fn build_client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // Client Version: TLS 1.2
        ch_body.extend_from_slice(&[0u8; 32]); // Random
        ch_body.push(0x00); // Session ID Length = 0
        ch_body.extend_from_slice(&[0x00, 0x02]); // Cipher Suites Length = 2
        ch_body.extend_from_slice(&[0x00, 0xFF]); // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        ch_body.push(0x01); // Compression Methods Length = 1
        ch_body.push(0x00); // Compression: null

        if !extensions.is_empty() {
            ch_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            ch_body.extend_from_slice(extensions);
        }

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_CLIENT_HELLO);
        let hs_len = ch_body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(&ch_body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // Record Version: TLS 1.0 (compat)
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    fn build_sni_extension(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        let entry_len = 1 + 2 + name.len();
        let list_len = entry_len;
        let ext_data_len = 2 + list_len;

        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes()); // EXT_SNI
        ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext.push(SNI_HOST_NAME);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        ext
    }

    fn build_ech_extension() -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_ECH.to_be_bytes());
        ext.extend_from_slice(&[0x00, 0x04]);
        ext.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        ext
    }

    fn build_supported_versions_extension(versions: &[u16]) -> Vec<u8> {
        let list_len = (versions.len() * 2) as u8;
        let ext_data_len = 1 + list_len as usize;

        let mut ext = Vec::new();
        ext.extend_from_slice(&0x002bu16.to_be_bytes()); // EXT_SUPPORTED_VERSIONS
        ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        ext.push(list_len);
        for v in versions {
            ext.extend_from_slice(&v.to_be_bytes());
        }
        ext
    }

    #[test]
    fn sni_extraction() {
        let exts = build_sni_extension("example.com");
        let pkt = build_client_hello(&exts);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.sni.as_deref(), Some("example.com"));
        assert_eq!(result.version, 0x0303);
        assert!(!result.ech_detected);
    }

    #[test]
    fn sni_subdomain() {
        let exts = build_sni_extension("www.sub.example.com");
        let pkt = build_client_hello(&exts);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.sni.as_deref(), Some("www.sub.example.com"));
    }

    #[test]
    fn sni_case_normalized() {
        let exts = build_sni_extension("Example.COM");
        let pkt = build_client_hello(&exts);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn no_extensions() {
        let pkt = build_client_hello(&[]);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.sni, None);
        assert_eq!(result.version, 0x0303);
        assert!(!result.ech_detected);
    }

    #[test]
    fn ech_detected() {
        let exts = build_ech_extension();
        let pkt = build_client_hello(&exts);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert!(result.ech_detected);
        assert_eq!(result.sni, None);
    }

    #[test]
    fn sni_with_ech() {
        let mut exts = build_sni_extension("example.com");
        exts.extend_from_slice(&build_ech_extension());
        let pkt = build_client_hello(&exts);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.sni.as_deref(), Some("example.com"));
        assert!(result.ech_detected);
    }

    #[test]
    fn tls_13_supported_versions() {
        let mut exts = build_sni_extension("tls13.example.com");
        exts.extend_from_slice(&build_supported_versions_extension(&[0x0304, 0x0303]));
        let pkt = build_client_hello(&exts);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.version, 0x0304);
        assert_eq!(result.sni.as_deref(), Some("tls13.example.com"));
    }

    #[test]
    fn tls_12_no_supported_versions() {
        let exts = build_sni_extension("tls12.example.com");
        let pkt = build_client_hello(&exts);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.version, 0x0303);
    }

    #[test]
    fn grease_values_skipped() {
        let exts = build_supported_versions_extension(&[0x3a3a, 0x0304, 0x0303]);
        let pkt = build_client_hello(&exts);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.version, 0x0304);
    }

    #[test]
    fn not_handshake_content_type() {
        let mut pkt = build_client_hello(&[]);
        pkt[0] = 0x17;
        assert!(parse_tls_client_hello(&pkt).is_none());
    }

    #[test]
    fn not_client_hello_handshake() {
        let mut pkt = build_client_hello(&[]);
        pkt[5] = 0x02;
        assert!(parse_tls_client_hello(&pkt).is_none());
    }

    #[test]
    fn truncated_record_header() {
        let pkt = [0x16, 0x03, 0x03];
        assert!(parse_tls_client_hello(&pkt).is_none());
    }

    #[test]
    fn truncated_handshake() {
        let pkt = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        assert!(parse_tls_client_hello(&pkt).is_none());
    }

    #[test]
    fn truncated_client_hello_body() {
        let mut pkt = build_client_hello(&build_sni_extension("example.com"));
        pkt.truncate(30);
        assert!(parse_tls_client_hello(&pkt).is_none());
    }

    #[test]
    fn empty_input() {
        assert!(parse_tls_client_hello(&[]).is_none());
    }

    // tls-parser akceptuje niskie wersje rekordu — filtrowanie robi classify_tls.
    #[test]
    fn record_version_too_low_accepted_by_parser() {
        let mut pkt = build_client_hello(&[]);
        pkt[1] = 0x02;
        assert!(parse_tls_client_hello(&pkt).is_some());
    }

    #[test]
    fn multiple_extensions_sni_last() {
        let mut exts = build_supported_versions_extension(&[0x0304, 0x0303]);
        exts.extend_from_slice(&build_ech_extension());
        exts.extend_from_slice(&build_sni_extension("last.example.com"));
        let pkt = build_client_hello(&exts);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.sni.as_deref(), Some("last.example.com"));
        assert_eq!(result.version, 0x0304);
        assert!(result.ech_detected);
    }

    #[test]
    fn unknown_extension_ignored() {
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x3b]); // Typ nieznany dla tls-parser
        exts.extend_from_slice(&[0x00, 0x02]);
        exts.extend_from_slice(&[0xAB, 0xCD]);
        exts.extend_from_slice(&build_sni_extension("example.com"));
        let pkt = build_client_hello(&exts);
        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn to_dpi_context_maps_fields() {
        let result = TlsParseResult {
            sni: Some("secure.example.com".into()),
            version: 0x0304,
            ech_detected: true,
        };
        let ctx = tls_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Tls));
        assert_eq!(ctx.tls_sni.as_deref(), Some("secure.example.com"));
        assert_eq!(ctx.tls_version, Some(0x0304));
        assert!(ctx.tls_ech_detected);
    }

    #[test]
    fn to_dpi_context_no_sni() {
        let result = TlsParseResult {
            sni: None,
            version: 0x0303,
            ech_detected: false,
        };
        let ctx = tls_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Tls));
        assert_eq!(ctx.tls_sni, None);
        assert_eq!(ctx.tls_version, Some(0x0303));
        assert!(!ctx.tls_ech_detected);
    }

    #[test]
    fn session_id_32_bytes() {
        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]);
        ch_body.extend_from_slice(&[0u8; 32]);
        ch_body.push(0x20); // Session ID Length = 32
        ch_body.extend_from_slice(&[0xAA; 32]);
        ch_body.extend_from_slice(&[0x00, 0x02]);
        ch_body.extend_from_slice(&[0x00, 0xFF]);
        ch_body.push(0x01);
        ch_body.push(0x00);
        let sni_ext = build_sni_extension("session.example.com");
        ch_body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&sni_ext);

        let mut hs = Vec::new();
        hs.push(HANDSHAKE_CLIENT_HELLO);
        let len = ch_body.len() as u32;
        hs.push((len >> 16) as u8);
        hs.push((len >> 8) as u8);
        hs.push(len as u8);
        hs.extend_from_slice(&ch_body);

        let mut pkt = Vec::new();
        pkt.push(CONTENT_TYPE_HANDSHAKE);
        pkt.extend_from_slice(&[0x03, 0x01]);
        pkt.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&hs);

        let result = parse_tls_client_hello(&pkt).unwrap();
        assert_eq!(result.sni.as_deref(), Some("session.example.com"));
    }
}
