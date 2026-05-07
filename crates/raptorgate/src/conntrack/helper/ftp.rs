use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::conntrack::helper::Helper;
use crate::conntrack::entry::ConntrackEntry;
use crate::conntrack::tuple::{Direction, Protocol};
use crate::conntrack::expectation::{Expectation, ExpectationTuple};

pub const FTP_NAME: &str = "ftp";
pub const FTP_DEFAULT_PORTS: &[u16] = &[21];

pub const FTP_EXPECT_TIMEOUT: Duration = Duration::from_secs(300);

pub struct FtpHelper;

impl FtpHelper {
    pub fn new() -> Self { Self }

    fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
        if s.len() < prefix.len() { return None; }
        
        let (head, tail) = s.split_at(prefix.len());
        
        if head.eq_ignore_ascii_case(prefix) { Some(tail) } else { None }
    }
    
    fn parse_port_args(s: &str) -> Option<(IpAddr, u16)> {
        let nums: Vec<u8> = s.split(|c: char| !c.is_ascii_digit())
            .filter(|tok| !tok.is_empty())
            .take(6)
            .map(|tok| tok.parse::<u8>().ok()).collect::<Option<Vec<_>>>()?;

        if nums.len() != 6 { return None; }

        let ip = IpAddr::V4(Ipv4Addr::new(nums[0], nums[1], nums[2], nums[3]));
        let port = ((nums[4] as u16) << 8) | (nums[5] as u16);

        if port == 0 { return None; }

        Some((ip, port))
    }

    fn extract_pasv_args(line: &str) -> Option<&str> {
        if !line.starts_with("227 ") && !line.starts_with("227-") {
            return None;
        }

        let lparen = line.find('(')?;
        let after_lparen = &line[lparen + 1..];
        let rparen_rel = after_lparen.find(')')?;

        Some(&after_lparen[..rparen_rel])
    }

    fn make_active_expectation(parent: &ConntrackEntry, dst_ip: IpAddr, dst_port: u16) -> Expectation {
        Expectation {
            id: 0,
            parent_id: parent.id,
            helper: FTP_NAME,
            tuple: ExpectationTuple {
                src_ip: Some(parent.original.dst_ip),
                src_port: None,
                dst_ip,
                dst_port,
                protocol: Protocol::Tcp,
            },
            zone: parent.zone,
            expires_at: Instant::now() + FTP_EXPECT_TIMEOUT,
            nat_hint: parent.nat.lock().clone(),
        }
    }

    fn make_passive_expectation(parent: &ConntrackEntry, dst_ip: IpAddr, dst_port: u16) -> Expectation {
        Expectation {
            id: 0,
            parent_id: parent.id,
            helper: FTP_NAME,
            tuple: ExpectationTuple {
                src_ip: Some(parent.original.src_ip),
                src_port: None,
                dst_ip,
                dst_port,
                protocol: Protocol::Tcp,
            },
            zone: parent.zone,
            expires_at: Instant::now() + FTP_EXPECT_TIMEOUT,
            nat_hint: parent.nat.lock().clone(),
        }
    }
}

impl Default for FtpHelper {
    fn default() -> Self { Self::new() }
}

impl Helper for FtpHelper {
    fn name(&self) -> &'static str { FTP_NAME }
    fn proto(&self) -> Protocol { Protocol::Tcp }
    fn ports(&self) -> &'static [u16] { FTP_DEFAULT_PORTS }

    fn inspect(&self, entry: &ConntrackEntry, payload: &[u8], dir: Direction) -> Vec<Expectation> {
        let mut out = Vec::new();

        // FTP control jest tekstowy ASCII. Binary payload nie obchodzi mnie
        let text = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return out,
        };

        for line in text.split("\r\n") {
            if line.is_empty() { continue; }

            match dir {
                Direction::Original => {
                    if let Some(rest) = Self::strip_prefix_ci(line, "PORT ") {
                        if let Some((ip, port)) = Self::parse_port_args(rest) {
                            out.push(Self::make_active_expectation(entry, ip, port));
                        }
                    }
                }
                Direction::Reply => {
                    if let Some(args) = Self::extract_pasv_args(line) {
                        if let Some((ip, port)) = Self::parse_port_args(&args) {
                            out.push(Self::make_passive_expectation(entry, ip, port));
                        }
                    }
                }
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::conntrack::tuple::FlowTuple;
    use crate::conntrack::proto::ProtoState;
    use crate::conntrack::proto::tcp::TcpProtoState;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn parent_entry() -> ConntrackEntry {
        let tuple = FlowTuple::new(
            ip(10, 0, 0, 5), 12345,        // klient
            ip(192, 168, 1, 100), 21,       // serwer FTP
            Protocol::Tcp,
        );

        ConntrackEntry::new(
            42,
            tuple,
            ProtoState::Tcp(TcpProtoState::default()),
            Duration::from_secs(3600),
            0,
        )
    }

    #[test]
    fn parse_port_basic() {
        let r = FtpHelper::parse_port_args("192,168,1,100,22,46").unwrap();

        assert_eq!(r.0, ip(192, 168, 1, 100));
        assert_eq!(r.1, 22 * 256 + 46);  // 5678
    }

    #[test]
    fn parse_port_with_trailing_garbage() {
        let r = FtpHelper::parse_port_args("10,0,0,1,0,80 ignored stuff").unwrap();

        assert_eq!(r.0, ip(10, 0, 0, 1));
        assert_eq!(r.1, 80);
    }

    #[test]
    fn parse_port_rejects_oversized_octet() {
        assert!(FtpHelper::parse_port_args("256,0,0,1,0,80").is_none());
    }

    #[test]
    fn parse_port_rejects_too_few_numbers() {
        assert!(FtpHelper::parse_port_args("1,2,3,4,5").is_none());
    }

    #[test]
    fn parse_port_rejects_zero_port() {
        assert!(FtpHelper::parse_port_args("10,0,0,1,0,0").is_none());
    }

    // ---- extract_pasv_args ----

    #[test]
    fn extract_pasv_basic() {
        let s = FtpHelper::extract_pasv_args("227 Entering Passive Mode (192,168,1,100,22,46).").unwrap();

        assert_eq!(s, "192,168,1,100,22,46");
    }

    #[test]
    fn extract_pasv_multiline_continuation() {
        let s = FtpHelper::extract_pasv_args("227-this is multi-line continuation (10,0,0,1,1,2)").unwrap();

        assert_eq!(s, "10,0,0,1,1,2");
    }

    #[test]
    fn extract_pasv_wrong_code() {
        assert!(FtpHelper::extract_pasv_args("226 Transfer complete.").is_none());
    }

    #[test]
    fn extract_pasv_no_parens() {
        assert!(FtpHelper::extract_pasv_args("227 something without parens").is_none());
    }

    #[test]
    fn inspect_detects_port_in_original() {
        let h = FtpHelper::new();
        let entry = parent_entry();

        let payload = b"PORT 10,0,0,5,40,0\r\n";
        let exps = h.inspect(&entry, payload, Direction::Original);

        assert_eq!(exps.len(), 1);

        let e = &exps[0];

        assert_eq!(e.parent_id, 42);
        assert_eq!(e.helper, FTP_NAME);
        assert_eq!(e.tuple.dst_ip, ip(10, 0, 0, 5));
        assert_eq!(e.tuple.dst_port, 40 * 256);

        assert_eq!(e.tuple.src_ip, Some(ip(192, 168, 1, 100)));
        assert_eq!(e.tuple.src_port, None);
        assert_eq!(e.zone, 0);
        assert_eq!(e.tuple.protocol, Protocol::Tcp);
    }

    #[test]
    fn inspect_detects_pasv_in_reply() {
        let h = FtpHelper::new();
        let entry = parent_entry();

        let payload = b"227 Entering Passive Mode (192,168,1,100,30,0).\r\n";
        let exps = h.inspect(&entry, payload, Direction::Reply);

        assert_eq!(exps.len(), 1);

        let e = &exps[0];

        assert_eq!(e.tuple.dst_ip, ip(192, 168, 1, 100));
        assert_eq!(e.tuple.dst_port, 30 * 256);
        assert_eq!(e.tuple.src_ip, Some(ip(10, 0, 0, 5)));
    }

    #[test]
    fn inspect_ignores_port_in_reply() {
        let h = FtpHelper::new();
        let entry = parent_entry();

        let payload = b"PORT 10,0,0,5,40,0\r\n";
        let exps = h.inspect(&entry, payload, Direction::Reply);

        assert!(exps.is_empty());
    }

    #[test]
    fn inspect_ignores_pasv_in_original() {
        let h = FtpHelper::new();
        let entry = parent_entry();

        let payload = b"227 Entering Passive Mode (192,168,1,100,30,0).\r\n";
        let exps = h.inspect(&entry, payload, Direction::Original);

        assert!(exps.is_empty());
    }

    #[test]
    fn inspect_returns_empty_on_binary() {
        let h = FtpHelper::new();
        let entry = parent_entry();

        let payload = &[0xFFu8, 0xFE, 0xFD, 0x80][..];
        let exps = h.inspect(&entry, payload, Direction::Original);

        assert!(exps.is_empty());
    }

    #[test]
    fn inspect_returns_empty_on_unrelated_text() {
        let h = FtpHelper::new();
        let entry = parent_entry();

        let payload = b"USER anonymous\r\nPASS guest@\r\n";
        let exps = h.inspect(&entry, payload, Direction::Original);

        assert!(exps.is_empty());
    }

    #[test]
    fn inspect_handles_pipelined_commands() {
        let h = FtpHelper::new();
        let entry = parent_entry();
        
        let payload = b"PORT 10,0,0,5,40,0\r\nPORT 10,0,0,5,40,1\r\n";
        let exps = h.inspect(&entry, payload, Direction::Original);

        assert_eq!(exps.len(), 2);
        assert_eq!(exps[0].tuple.dst_port, 40 * 256);
        assert_eq!(exps[1].tuple.dst_port, 40 * 256 + 1);
    }

    #[test]
    fn inspect_inherits_zone() {
        let h = FtpHelper::new();
        
        let tuple = FlowTuple::new(
            ip(10, 0, 0, 5), 12345,
            ip(192, 168, 1, 100), 21,
            Protocol::Tcp,
        );

        let entry = ConntrackEntry::new(
            42, tuple,
            ProtoState::Tcp(TcpProtoState::default()),
            Duration::from_secs(3600),
            7,  // zone 7
        );

        let exps = h.inspect(&entry, b"PORT 10,0,0,5,40,0\r\n", Direction::Original);

        assert_eq!(exps[0].zone, 7);
    }

    #[test]
    fn inspect_inherits_nat_hint() {
        use crate::conntrack::entry::NatTransform;

        let h = FtpHelper::new();
        let entry = parent_entry();

        *entry.nat.lock() = Some(NatTransform {
            rule_id: "rule-1".to_string(),
            binding_id: 99,
            manip_bits: 0,
            src_manip: None,
            dst_manip: None,
            allocated_ip: None,
            proto: Protocol::Tcp,
            allocated_port: Some(50000),
        });

        let exps = h.inspect(&entry, b"PORT 10,0,0,5,40,0\r\n", Direction::Original);
        let hint = exps[0].nat_hint.as_ref().unwrap();

        assert_eq!(hint.rule_id, "rule-1");
        assert_eq!(hint.binding_id, 99);
    }
}