use crate::dpi::context::DpiContext;
use crate::dpi::AppProto;

// Wynik parsowania banneru SSH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshParseResult {
    pub proto_version: String,
    pub software: String,
}

// Parsuje banner SSH.
pub fn parse_ssh(buf: &[u8]) -> Option<SshParseResult> {
    if !buf.starts_with(b"SSH-") {
        return None;
    }

    let line_end = buf.iter().position(|&b| b == b'\n');
    let line = match line_end {
        Some(pos) => &buf[4..pos],
        None if buf.len() <= 255 => &buf[4..],
        None => return None,
    };

    let line = line.strip_suffix(b"\r").unwrap_or(line);

    let dash_pos = line.iter().position(|&b| b == b'-')?;
    let proto_version = std::str::from_utf8(&line[..dash_pos]).ok()?;

    if !proto_version.starts_with("1.") && proto_version != "2.0" {
        return None;
    }

    let rest = &line[dash_pos + 1..];
    let software_end = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
    let software = std::str::from_utf8(&rest[..software_end]).ok()?;

    if software.is_empty() {
        return None;
    }

    Some(SshParseResult {
        proto_version: proto_version.to_owned(),
        software: software.to_owned(),
    })
}

pub fn ssh_to_dpi_context(result: &SshParseResult) -> DpiContext {
    DpiContext {
        app_proto: Some(AppProto::Ssh),
        ssh_proto_version: Some(result.proto_version.clone()),
        ssh_software: Some(result.software.clone()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssh_banner() {
        let buf = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
        let r = parse_ssh(buf).unwrap();
        assert_eq!(r.proto_version, "2.0");
        assert_eq!(r.software, "OpenSSH_8.9p1");
    }

    #[test]
    fn dropbear_banner() {
        let buf = b"SSH-2.0-dropbear_2022.83\r\n";
        let r = parse_ssh(buf).unwrap();
        assert_eq!(r.proto_version, "2.0");
        assert_eq!(r.software, "dropbear_2022.83");
    }

    #[test]
    fn libssh_banner() {
        let buf = b"SSH-2.0-libssh_0.10.6\r\n";
        let r = parse_ssh(buf).unwrap();
        assert_eq!(r.software, "libssh_0.10.6");
    }

    #[test]
    fn bare_lf_terminator() {
        let buf = b"SSH-2.0-OpenSSH_9.0\n";
        let r = parse_ssh(buf).unwrap();
        assert_eq!(r.proto_version, "2.0");
        assert_eq!(r.software, "OpenSSH_9.0");
    }

    #[test]
    fn no_terminator_short_buf() {
        let buf = b"SSH-2.0-PuTTY_Release_0.78";
        let r = parse_ssh(buf).unwrap();
        assert_eq!(r.software, "PuTTY_Release_0.78");
    }

    #[test]
    fn ssh_v1() {
        let buf = b"SSH-1.99-OpenSSH_3.9\r\n";
        let r = parse_ssh(buf).unwrap();
        assert_eq!(r.proto_version, "1.99");
        assert_eq!(r.software, "OpenSSH_3.9");
    }

    #[test]
    fn comment_ignored() {
        let buf = b"SSH-2.0-MyServer extra comment data\r\n";
        let r = parse_ssh(buf).unwrap();
        assert_eq!(r.software, "MyServer");
    }

    #[test]
    fn invalid_prefix() {
        assert!(parse_ssh(b"HTTP/1.1 200 OK\r\n").is_none());
    }

    #[test]
    fn too_short() {
        assert!(parse_ssh(b"SSH").is_none());
    }

    #[test]
    fn missing_software() {
        assert!(parse_ssh(b"SSH-2.0-\r\n").is_none());
    }

    #[test]
    fn invalid_proto_version() {
        assert!(parse_ssh(b"SSH-3.0-Something\r\n").is_none());
    }

    #[test]
    fn to_dpi_context_maps_fields() {
        let result = SshParseResult {
            proto_version: "2.0".into(),
            software: "OpenSSH_8.9p1".into(),
        };
        let ctx = ssh_to_dpi_context(&result);
        assert_eq!(ctx.app_proto, Some(AppProto::Ssh));
        assert_eq!(ctx.ssh_proto_version.as_deref(), Some("2.0"));
        assert_eq!(ctx.ssh_software.as_deref(), Some("OpenSSH_8.9p1"));
    }
}
