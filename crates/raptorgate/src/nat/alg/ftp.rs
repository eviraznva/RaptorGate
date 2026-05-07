use std::net::IpAddr;
use std::ops::Range;

use anyhow::{Context, Result, anyhow};

use crate::dpi::{AppProto, DpiContext, FtpRewriteKind};
use crate::nat::packet::{
    packet_endpoints_from_ethernet, refresh_after_payload_resize, transport_payload_range,
};

/// Rewrite payloadu FTP w miejscu. Aktywuje się tylko gdy `dpi_ctx.app_proto == Ftp`
/// oraz DPI rozpoznał komendę PORT/PASV/EPRT/EPSV i zapisał `ftp_data_endpoint`
pub fn ftp_alg_rewrite(packet: &mut Vec<u8>, dpi_ctx: &DpiContext) -> Result<bool> {
    if dpi_ctx.app_proto != Some(AppProto::Ftp) {
        return Ok(false);
    }

    let Some(endpoint) = dpi_ctx.ftp_data_endpoint.as_ref() else {
        tracing::trace!("ftp alg skipped: dpi context has no data endpoint");
        
        return Ok(false);
    };

    let (public_src_ip, _server_ip) = packet_endpoints_from_ethernet(packet.as_slice())
        .ok_or_else(|| anyhow!("ftp alg: cannot resolve packet endpoints"))?;

    let tcp_payload = transport_payload_range(packet.as_slice())
        .ok_or_else(|| anyhow!("ftp alg: cannot resolve transport payload"))?;

    let replacement = render_ftp_rewrite(endpoint.rewrite_kind, public_src_ip, endpoint.port)
        .ok_or_else(|| anyhow!("ftp alg: cannot render replacement"))?;

    let range = (tcp_payload.start + endpoint.payload_offset)..(tcp_payload.start + endpoint.payload_offset + endpoint.payload_len);

    rewrite_transport_payload_segment(packet, range, &replacement).context("ftp alg payload range out of bounds")?;

    if !refresh_after_payload_resize(packet.as_mut_slice()) {
        return Err(anyhow!("ftp alg: failed to refresh checksums"));
    }

    tracing::debug!(
          rewrite_kind = ?endpoint.rewrite_kind,
          replacement = %replacement,
          packet_len = packet.len(),
          "ftp alg rewrote payload"
      );

    Ok(true)
}

fn render_ftp_rewrite(kind: FtpRewriteKind, ip: IpAddr, port: u16) -> Option<String> {
    match kind {
        FtpRewriteKind::Port | FtpRewriteKind::Pasv => render_port_csv(ip, port),
        FtpRewriteKind::Eprt { delimiter } => render_eprt(delimiter, ip, port),
        FtpRewriteKind::Epsv { delimiter } => Some(render_epsv(delimiter, port)),
    }
}

fn render_port_csv(ip: IpAddr, port: u16) -> Option<String> {
    let IpAddr::V4(ipv4) = ip else { return None; };
    
    let o = ipv4.octets();
    
    Some(format!("{},{},{},{},{},{}", o[0], o[1], o[2], o[3], port >> 8, port & 0xff))
}

fn render_eprt(delimiter: u8, ip: IpAddr, port: u16) -> Option<String> {
    let family = match ip { IpAddr::V4(_) => 1, IpAddr::V6(_) => 2 };
    
    let d = char::from(delimiter);
    
    Some(format!("{d}{family}{d}{ip}{d}{port}{d}"))
}

fn render_epsv(delimiter: u8, port: u16) -> String {
    let d = char::from(delimiter);
    
    format!("{d}{d}{d}{port}{d}")
}

fn rewrite_transport_payload_segment(packet: &mut Vec<u8>, range: Range<usize>, replacement: &str) -> Result<()> {
    if range.start > range.end || range.end > packet.len() {
        return Err(anyhow!("rewrite range out of bounds"));
    }
    
    packet.splice(range, replacement.as_bytes().iter().copied());
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_port_csv_formats_ipv4_correctly() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 5));
        let csv = render_port_csv(ip, 0x1234).unwrap();
        
        assert_eq!(csv, "192,168,1,5,18,52");
    }

    #[test]
    fn render_eprt_uses_delimiter() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        
        assert_eq!(render_eprt(b'|', ip, 8080), Some("|1|10.0.0.1|8080|".into()));
    }

    #[test]
    fn render_epsv_omits_address() {
        assert_eq!(render_epsv(b'|', 8080), "|||8080|");
    }
}