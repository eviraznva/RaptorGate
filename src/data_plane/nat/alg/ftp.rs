/// Ten moduł implementuje obsługę Application Layer Gateway (ALG) dla protokołu FTP w silniku NAT.
/// Pozwala na dynamiczną translację adresów i portów w poleceniach FTP (np. PORT, PASV, EPRT, EPSV),
/// a także automatyczne tworzenie powiązań NAT dla połączeń danych FTP.

use std::net::IpAddr;
use std::ops::Range;
use std::time::Duration;

use crate::data_plane::nat::engine::{binding_timeout_for, build_binding, NatEngine};

use crate::data_plane::nat::packet::{
    packet_endpoints_from_ethernet, refresh_after_payload_resize, transport_payload_range,
};

use crate::dpi::{AppProto, DpiContext, FtpRewriteKind};
use crate::data_plane::nat::types::{FlowTuple, L4Proto, NatBinding};

impl NatEngine {
    /// Przetwarza pakiet FTP ALG: wykrywa polecenia FTP wymagające translacji,
    /// modyfikuje payload TCP oraz tworzy powiązania NAT dla połączeń danych FTP.
    pub fn process_ftp_alg(&mut self, data: &mut Vec<u8>, dpi_ctx: &DpiContext) {
        if dpi_ctx.app_proto != Some(AppProto::Ftp) {
            return;
        }

        let Some(endpoint) = dpi_ctx.ftp_data_endpoint.as_ref() else {
            tracing::trace!("ftp alg skipped: dpi context has no data endpoint");
            return;
        };

        tracing::trace!(
            rewrite_kind = ?endpoint.rewrite_kind,
            endpoint_ip = %endpoint.ip,
            endpoint_port = endpoint.port,
            payload_offset = endpoint.payload_offset,
            payload_len = endpoint.payload_len,
            packet_len = data.len(),
            "ftp alg processing packet"
        );

        let Some((public_src_ip, server_ip)) = packet_endpoints_from_ethernet(data.as_slice()) else {
            tracing::trace!("ftp alg skipped: unable to resolve packet endpoints");
            return;
        };

        let Some(tcp_payload) = transport_payload_range(data.as_slice()) else {
            tracing::trace!("ftp alg skipped: unable to resolve transport payload range");
            return;
        };

        let Some(replacement) = render_ftp_rewrite(endpoint.rewrite_kind, public_src_ip, endpoint.port) else {
            tracing::debug!(
                rewrite_kind = ?endpoint.rewrite_kind,
                public_src_ip = %public_src_ip,
                endpoint_port = endpoint.port,
                "ftp alg skipped: unable to render replacement payload"
            );
            return;
        };

        let range = (tcp_payload.start + endpoint.payload_offset)
            ..(tcp_payload.start + endpoint.payload_offset + endpoint.payload_len);

        if !rewrite_transport_payload_segment(data, range, &replacement) {
            tracing::warn!("ftp alg failed to rewrite payload segment");
            return;
        }

        if !refresh_after_payload_resize(data.as_mut_slice()) {
            tracing::warn!("ftp alg failed to refresh checksums after payload rewrite");
            return;
        }

        tracing::debug!(
            rewrite_kind = ?endpoint.rewrite_kind,
            public_src_ip = %public_src_ip,
            server_ip = %server_ip,
            replacement = %replacement,
            packet_len = data.len(),
            "ftp alg rewrote payload"
        );

        if endpoint.rewrite_kind.is_active_command() {
            if let Some(binding) = build_active_ftp_binding(self, public_src_ip, endpoint.port, server_ip) {
                tracing::debug!(
                    binding_id = binding.binding_id,
                    translated = ?binding.translated_forward,
                    "ftp alg created active data binding"
                );
                
                self.insert_binding(binding);
            } else {
                tracing::debug!(
                    public_src_ip = %public_src_ip,
                    server_ip = %server_ip,
                    data_port = endpoint.port,
                    "ftp alg could not pre-create active data binding"
                );
            }
        }
    }
}

/// Buduje powiązanie NAT dla aktywnego połączenia danych FTP (PORT)
fn build_active_ftp_binding(
    engine: &mut NatEngine,
    public_ip: IpAddr,
    data_port: u16,
    server_ip: IpAddr,
) -> Option<NatBinding> {
    let private_ip = engine.lookup_original_src(&public_ip)?;
    
    tracing::trace!(%public_ip, %private_ip, %server_ip, data_port, "ftp alg resolved private endpoint for active binding");
    
    let original_forward = FlowTuple {
        src_ip: server_ip,
        src_port: 20,
        dst_ip: public_ip,
        dst_port: data_port,
        proto: L4Proto::Tcp,
    };
    
    let translated_forward = FlowTuple {
        src_ip: server_ip,
        src_port: 20,
        dst_ip: private_ip,
        dst_port: data_port,
        proto: L4Proto::Tcp,
    };

    Some(build_binding(
        engine.next_binding_id(),
        "ftp-alg".to_string(),
        original_forward,
        translated_forward,
        None,
        Duration::from_secs(120).min(binding_timeout_for(L4Proto::Tcp)),
    ))
}

/// Renderuje nową wartość polecenia FTP po translacji adresu/portu
fn render_ftp_rewrite(kind: FtpRewriteKind, ip: IpAddr, port: u16) -> Option<String> {
    let rendered = match kind {
        FtpRewriteKind::Port | FtpRewriteKind::Pasv => render_port_csv(ip, port),
        FtpRewriteKind::Eprt { delimiter } => render_eprt(delimiter, ip, port),
        FtpRewriteKind::Epsv { delimiter } => Some(render_epsv(delimiter, port)),
    };
    
    tracing::trace!(rewrite_kind = ?kind, %ip, port, ?rendered, "ftp alg rendered replacement");
    
    rendered
}

/// Renderuje polecenie PORT/PASV w formacie CSV (dla IPv4)
fn render_port_csv(ip: IpAddr, port: u16) -> Option<String> {
    let IpAddr::V4(ipv4) = ip else {
        return None;
    };
    
    let octets = ipv4.octets();
    
    Some(format!(
        "{},{},{},{},{},{}",
        octets[0],
        octets[1],
        octets[2],
        octets[3],
        port >> 8,
        port & 0xff
    ))
}

/// Renderuje polecenie EPRT (IPv4/IPv6)
fn render_eprt(delimiter: u8, ip: IpAddr, port: u16) -> Option<String> {
    let family = match ip {
        IpAddr::V4(_) => 1,
        IpAddr::V6(_) => 2,
    };
    
    let delimiter = char::from(delimiter);
    
    Some(format!("{delimiter}{family}{delimiter}{ip}{delimiter}{port}{delimiter}"))
}

/// Renderuje polecenie EPSV
fn render_epsv(delimiter: u8, port: u16) -> String {
    let delimiter = char::from(delimiter);
    
    format!("{delimiter}{delimiter}{delimiter}{port}{delimiter}")
}

/// Zastępuje fragment payloadu TCP nową wartością (adres/port po translacji)
fn rewrite_transport_payload_segment(
    data: &mut Vec<u8>,
    range: Range<usize>,
    replacement: &str,
) -> bool {
    if range.start > range.end || range.end > data.len() {
        tracing::warn!(range = ?range, buffer_len = data.len(), "ftp alg payload rewrite range out of bounds");
        return false;
    }

    tracing::trace!(range = ?range, replacement_len = replacement.len(), "ftp alg rewriting payload segment");
    data.splice(range, replacement.as_bytes().iter().copied());
    
    true
}
