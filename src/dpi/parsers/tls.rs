use crate::dpi::context::DpiContext;
use crate::dpi::AppProto;

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SNI: u16 = 0x0000;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_ECH: u16 = 0xfe0d;
const SNI_HOST_NAME: u8 = 0x00;

// Wynik parsowania TLS ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsParseResult {
    pub sni: Option<String>,
    pub version: u16,
    pub ech_detected: bool,
}

// Parsuje TLS ClientHello i wyodrębnia SNI, wersję i obecność ECH.
pub fn parse_tls_client_hello(buf: &[u8]) -> Option<TlsParseResult> {
    let mut c = Cursor::new(buf);

    // TLS Record Header (5 bajtów)
    let content_type = c.read_u8()?;
    if content_type != CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    let record_version = c.read_u16()?;
    if record_version < 0x0301 || record_version > 0x0304 {
        return None;
    }
    let record_len = c.read_u16()? as usize;
    let record_payload = c.read_bytes(record_len)?;

    let mut hs = Cursor::new(record_payload);
    let hs_type = hs.read_u8()?;
    if hs_type != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let hs_len = hs.read_u24()? as usize;
    let ch_data = hs.read_bytes(hs_len)?;

    let mut ch = Cursor::new(ch_data);
    let client_version = ch.read_u16()?;
    ch.skip(32)?; // Random
    let session_id_len = ch.read_u8()? as usize;
    ch.skip(session_id_len)?;
    let cipher_suites_len = ch.read_u16()? as usize;
    ch.skip(cipher_suites_len)?;
    let compression_len = ch.read_u8()? as usize;
    ch.skip(compression_len)?;

    if ch.remaining() < 2 {
        return Some(TlsParseResult {
            sni: None,
            version: client_version,
            ech_detected: false,
        });
    }

    let extensions_len = ch.read_u16()? as usize;
    let ext_data = ch.read_bytes(extensions_len)?;

    let mut sni = None;
    let mut ech_detected = false;
    let mut real_version = client_version;

    let mut ext = Cursor::new(ext_data);
    while ext.remaining() >= 4 {
        let ext_type = ext.read_u16()?;
        let ext_len = ext.read_u16()? as usize;
        let ext_body = ext.read_bytes(ext_len)?;

        match ext_type {
            EXT_SNI => {
                sni = parse_sni_extension(ext_body);
            }
            EXT_ECH => {
                ech_detected = true;
            }
            EXT_SUPPORTED_VERSIONS => {
                if let Some(v) = parse_supported_versions(ext_body) {
                    real_version = v;
                }
            }
            _ => {}
        }
    }

    Some(TlsParseResult {
        sni,
        version: real_version,
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

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    let mut c = Cursor::new(data);
    let _list_len = c.read_u16()?;

    while c.remaining() >= 3 {
        let name_type = c.read_u8()?;
        let name_len = c.read_u16()? as usize;
        let name_data = c.read_bytes(name_len)?;

        if name_type == SNI_HOST_NAME {
            return std::str::from_utf8(name_data).ok().map(|s| s.to_lowercase());
        }
    }
    None
}

// W ClientHello: 1 bajt długości listy, potem pary 2-bajtowych wersji.
fn parse_supported_versions(data: &[u8]) -> Option<u16> {
    let mut c = Cursor::new(data);
    let list_len = c.read_u8()? as usize;
    if list_len < 2 || list_len % 2 != 0 {
        return None;
    }
    let versions_data = c.read_bytes(list_len)?;
    let mut highest = 0u16;
    let mut vc = Cursor::new(versions_data);
    while vc.remaining() >= 2 {
        let v = vc.read_u16()?;
        if v > highest && !is_grease(v) {
            highest = v;
        }
    }
    (highest > 0).then_some(highest)
}

fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.pos >= self.data.len() {
            return None;
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Some(v)
    }

    fn read_u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.data.len() {
            return None;
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }

    fn read_u24(&mut self) -> Option<u32> {
        if self.pos + 3 > self.data.len() {
            return None;
        }
        let v = (self.data[self.pos] as u32) << 16
            | (self.data[self.pos + 1] as u32) << 8
            | self.data[self.pos + 2] as u32;
        self.pos += 3;
        Some(v)
    }

    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some(slice)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        if self.pos + len > self.data.len() {
            return None;
        }
        self.pos += len;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: buduje minimalny TLS ClientHello z podanymi rozszerzeniami.
    fn build_client_hello(extensions: &[u8]) -> Vec<u8> {
        build_client_hello_with_version(0x0303, extensions)
    }

    fn build_client_hello_with_version(client_version: u16, extensions: &[u8]) -> Vec<u8> {
        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&client_version.to_be_bytes()); // Client Version
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
        let entry_len = 1 + 2 + name.len(); // type + name_len + name
        let list_len = entry_len;
        let ext_data_len = 2 + list_len; // list_len_field + list

        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SNI.to_be_bytes());
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
        ext.extend_from_slice(&[0x00, 0x04]); // 4 bajty danych (fikcyjne)
        ext.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        ext
    }

    fn build_supported_versions_extension(versions: &[u16]) -> Vec<u8> {
        let list_len = (versions.len() * 2) as u8;
        let ext_data_len = 1 + list_len as usize;

        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
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
        pkt[0] = 0x17; // Application Data zamiast Handshake
        assert!(parse_tls_client_hello(&pkt).is_none());
    }

    #[test]
    fn not_client_hello_handshake() {
        let mut pkt = build_client_hello(&[]);
        pkt[5] = 0x02; // ServerHello zamiast ClientHello
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

    #[test]
    fn record_version_too_low() {
        let mut pkt = build_client_hello(&[]);
        pkt[1] = 0x02; // SSL 2.0
        assert!(parse_tls_client_hello(&pkt).is_none());
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
        exts.extend_from_slice(&[0x00, 0x17]); // Unknown extension type
        exts.extend_from_slice(&[0x00, 0x02]); // Length
        exts.extend_from_slice(&[0xAB, 0xCD]); // Data
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
    fn is_grease_values() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0x2a2a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0303));
        assert!(!is_grease(0x0304));
        assert!(!is_grease(0x0000));
    }

    #[test]
    fn session_id_32_bytes() {
        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        ch_body.extend_from_slice(&[0u8; 32]); // Random
        ch_body.push(0x20); // Session ID Length = 32
        ch_body.extend_from_slice(&[0xAA; 32]); // Session ID
        ch_body.extend_from_slice(&[0x00, 0x02]); // Cipher Suites Length
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
