use std::net::{IpAddr, Ipv4Addr};

use crate::dpi::context::{DpiContext, FtpDataEndpoint, FtpRewriteKind};
use crate::dpi::AppProto;

// Wynik parsowania sesji FTP z ekstrakcją PORT/PASV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpParseResult {
    pub data_endpoint: Option<FtpDataEndpoint>,
}

// Identyfikuje ruch FTP i ekstrahuje dane PORT/PASV/EPRT/EPSV.
pub fn parse_ftp(buf: &[u8]) -> Option<FtpParseResult> {
    if buf.len() < 4 || !is_ftp_start(buf) {
        return None;
    }
    Some(FtpParseResult {
        data_endpoint: find_data_endpoint(buf),
    })
}

pub fn ftp_to_dpi_context(result: &FtpParseResult) -> DpiContext {
    DpiContext {
        app_proto: Some(AppProto::Ftp),
        ftp_data_endpoint: result.data_endpoint.clone(),
        ..Default::default()
    }
}

fn is_ftp_start(buf: &[u8]) -> bool {
    const SERVER: &[&[u8]] = &[b"220 ", b"220-", b"227 ", b"229 ", b"150 ", b"226 ", b"230 ", b"331 ", b"530 "];
    const CLIENT: &[&[u8]] = &[
        b"USER", b"PASS", b"PORT", b"PASV", b"EPRT", b"EPSV",
        b"RETR", b"STOR", b"LIST", b"QUIT", b"CWD ", b"TYPE",
        b"SYST", b"FEAT",
    ];
    SERVER.iter().chain(CLIENT.iter()).any(|p| buf.starts_with(p))
}

// Skanuje bufor linia po linii w poszukiwaniu PORT/PASV/EPRT/EPSV.
fn find_data_endpoint(buf: &[u8]) -> Option<FtpDataEndpoint> {
    let mut pos = 0;
    while pos < buf.len() {
        let remaining = &buf[pos..];
        let line_len = remaining
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(remaining.len());
        let line = &remaining[..line_len];

        let result = try_parse_port(line, pos)
            .or_else(|| try_parse_pasv(line, pos))
            .or_else(|| try_parse_eprt(line, pos))
            .or_else(|| try_parse_epsv(line, pos));
        if result.is_some() {
            return result;
        }
        pos += line_len;
    }
    None
}

// Tryb aktywny klient podaje swój IP i port dla kanału danych.
fn try_parse_port(line: &[u8], offset: usize) -> Option<FtpDataEndpoint> {
    if !line.starts_with(b"PORT ") {
        return None;
    }
    let value = std::str::from_utf8(&line[5..]).ok()?.trim_end();
    let (ip, port) = parse_host_port_csv(value)?;
    Some(FtpDataEndpoint {
        ip: IpAddr::V4(ip),
        port,
        payload_offset: offset + 5,
        payload_len: value.len(),
        rewrite_kind: FtpRewriteKind::Port,
    })
}

// Tryb pasywny serwer podaje swój IP i port dla kanału danych.
fn try_parse_pasv(line: &[u8], offset: usize) -> Option<FtpDataEndpoint> {
    if !line.starts_with(b"227 ") {
        return None;
    }
    let s = std::str::from_utf8(line).ok()?;
    let open = s.find('(')?;
    let close = s[open..].find(')')? + open;
    let (ip, port) = parse_host_port_csv(&s[open + 1..close])?;
    Some(FtpDataEndpoint {
        ip: IpAddr::V4(ip),
        port,
        payload_offset: offset + open + 1,
        payload_len: close - open - 1,
        rewrite_kind: FtpRewriteKind::Pasv,
    })
}

// Rozszerzony tryb aktywny obsługuje IPv4 i IPv6.
fn try_parse_eprt(line: &[u8], offset: usize) -> Option<FtpDataEndpoint> {
    if !line.starts_with(b"EPRT ") {
        return None;
    }
    let args = std::str::from_utf8(&line[5..]).ok()?.trim_end();
    let d = args.as_bytes().first().copied()?;
    let parts: Vec<&str> = args.split(d as char).collect();
    if parts.len() < 5 {
        return None;
    }
    let ip: IpAddr = parts[2].parse().ok()?;
    let port: u16 = parts[3].parse().ok()?;
    Some(FtpDataEndpoint {
        ip,
        port,
        payload_offset: offset + 5,
        payload_len: args.len(),
        rewrite_kind: FtpRewriteKind::Eprt { delimiter: d },
    })
}

// Rozszerzony tryb pasywny serwer podaje tylko port.
fn try_parse_epsv(line: &[u8], offset: usize) -> Option<FtpDataEndpoint> {
    if !line.starts_with(b"229 ") {
        return None;
    }
    let s = std::str::from_utf8(line).ok()?;
    let open = s.find('(')?;
    let close = s[open..].find(')')? + open;
    let inner = &s[open + 1..close];
    let d = inner.as_bytes().first().copied()?;
    let parts: Vec<&str> = inner.split(d as char).collect();
    if parts.len() < 4 {
        return None;
    }
    let port: u16 = parts[3].parse().ok()?;
    Some(FtpDataEndpoint {
        ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port,
        payload_offset: offset + open + 1,
        payload_len: inner.len(),
        rewrite_kind: FtpRewriteKind::Epsv { delimiter: d },
    })
}

// Parsuje "h1,h2,h3,h4,p1,p2" na (IPv4, port).
fn parse_host_port_csv(s: &str) -> Option<(Ipv4Addr, u16)> {
    let p: Vec<&str> = s.split(',').collect();
    if p.len() != 6 {
        return None;
    }
    let h: [u8; 4] = [
        p[0].parse().ok()?,
        p[1].parse().ok()?,
        p[2].parse().ok()?,
        p[3].parse().ok()?,
    ];
    let port = p[4].parse::<u16>().ok()? * 256 + p[5].parse::<u16>().ok()?;
    Some((Ipv4Addr::new(h[0], h[1], h[2], h[3]), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_banner() {
        let r = parse_ftp(b"220 Welcome to FTP\r\n").unwrap();
        assert!(r.data_endpoint.is_none());
    }

    #[test]
    fn multiline_banner() {
        let r = parse_ftp(b"220-Welcome\r\n220 Ready\r\n").unwrap();
        assert!(r.data_endpoint.is_none());
    }

    #[test]
    fn port_command() {
        let buf = b"PORT 192,168,1,5,4,1\r\n";
        let r = parse_ftp(buf).unwrap();
        let ep = r.data_endpoint.unwrap();
        assert_eq!(ep.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(ep.port, 1025);
        assert_eq!(ep.payload_offset, 5);
        assert_eq!(ep.payload_len, b"192,168,1,5,4,1".len());
        assert_eq!(ep.rewrite_kind, FtpRewriteKind::Port);
    }

    #[test]
    fn pasv_response() {
        let buf = b"227 Entering Passive Mode (10,0,0,1,39,5)\r\n";
        let r = parse_ftp(buf).unwrap();
        let ep = r.data_endpoint.unwrap();
        assert_eq!(ep.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(ep.port, 39 * 256 + 5);
        assert_eq!(ep.rewrite_kind, FtpRewriteKind::Pasv);
    }

    #[test]
    fn eprt_ipv4() {
        let buf = b"EPRT |1|192.168.1.1|6446|\r\n";
        let r = parse_ftp(buf).unwrap();
        let ep = r.data_endpoint.unwrap();
        assert_eq!(ep.ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(ep.port, 6446);
        assert_eq!(ep.rewrite_kind, FtpRewriteKind::Eprt { delimiter: b'|' });
    }

    #[test]
    fn eprt_ipv6() {
        let buf = b"EPRT |2|::1|6446|\r\n";
        let r = parse_ftp(buf).unwrap();
        let ep = r.data_endpoint.unwrap();
        assert_eq!(ep.ip, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(ep.port, 6446);
        assert_eq!(ep.rewrite_kind, FtpRewriteKind::Eprt { delimiter: b'|' });
    }

    #[test]
    fn epsv_response() {
        let buf = b"229 Entering Extended Passive Mode (|||6446|)\r\n";
        let r = parse_ftp(buf).unwrap();
        let ep = r.data_endpoint.unwrap();
        assert_eq!(ep.ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(ep.port, 6446);
        assert_eq!(ep.rewrite_kind, FtpRewriteKind::Epsv { delimiter: b'|' });
    }

    #[test]
    fn port_in_later_line() {
        let buf = b"220 Welcome\r\nUSER anonymous\r\nPORT 10,0,0,2,0,21\r\n";
        let r = parse_ftp(buf).unwrap();
        let ep = r.data_endpoint.unwrap();
        assert_eq!(ep.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(ep.port, 21);
        assert_eq!(ep.payload_offset, 34);
    }

    #[test]
    fn pasv_in_later_line() {
        let buf = b"220 Ready\r\n227 Entering Passive Mode (172,16,0,1,200,100)\r\n";
        let r = parse_ftp(buf).unwrap();
        let ep = r.data_endpoint.unwrap();
        assert_eq!(ep.ip, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
        assert_eq!(ep.port, 200 * 256 + 100);
    }

    #[test]
    fn not_ftp() {
        assert!(parse_ftp(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn too_short() {
        assert!(parse_ftp(b"22").is_none());
    }

    #[test]
    fn empty() {
        assert!(parse_ftp(b"").is_none());
    }

    #[test]
    fn malformed_port() {
        let r = parse_ftp(b"PORT invalid\r\n").unwrap();
        assert!(r.data_endpoint.is_none());
    }

    #[test]
    fn malformed_pasv() {
        let r = parse_ftp(b"227 Entering Passive Mode (bad)\r\n").unwrap();
        assert!(r.data_endpoint.is_none());
    }

    #[test]
    fn user_command_no_endpoint() {
        let r = parse_ftp(b"USER anonymous\r\n").unwrap();
        assert!(r.data_endpoint.is_none());
    }

    #[test]
    fn to_dpi_context_with_endpoint() {
        let result = FtpParseResult {
            data_endpoint: Some(FtpDataEndpoint {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: 2000,
                payload_offset: 0,
                payload_len: 25,
                rewrite_kind: FtpRewriteKind::Port,
            }),
        };
        let ctx = ftp_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Ftp));
        assert!(ctx.ftp_data_endpoint.is_some());
        assert_eq!(ctx.ftp_data_endpoint.unwrap().port, 2000);
    }

    #[test]
    fn to_dpi_context_without_endpoint() {
        let result = FtpParseResult { data_endpoint: None };
        let ctx = ftp_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Ftp));
        assert!(ctx.ftp_data_endpoint.is_none());
    }
}
