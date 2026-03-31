/// Ten moduł zawiera funkcje i struktury do parsowania, modyfikowania i translacji pakietów sieciowych dla NAT.

use std::io::Cursor;
use std::ops::Range;
use std::net::IpAddr;

use etherparse::{
    Ethernet2Header, IpHeaders, NetSlice, SlicedPacket, TcpHeader, TransportSlice, UdpHeader,
};

use crate::data_plane::nat::types::{FlowTuple, L4Proto};

/// Stała określająca długość nagłówka Ethernet
pub(crate) const ETH_HEADER_LEN: usize = Ethernet2Header::LEN;

/// Enum reprezentujący własnościowy nagłówek warstwy transportowej (TCP, UDP, ICMP)
#[derive(Clone, Debug)]
pub(crate) enum TransportHeaderOwned {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp,
}

impl TransportHeaderOwned {
    /// Zwraca długość nagłówka warstwy transportowej
    fn header_len(&self) -> usize {
        match self {
            Self::Tcp(header) => header.header_len(),
            Self::Udp(_) => UdpHeader::LEN,
            Self::Icmp => 0,
        }
    }
}

/// Struktura reprezentująca sparsowany pakiet wraz z informacjami o flow i nagłówkach
#[derive(Clone, Debug)]
pub(crate) struct ParsedPacket {
    pub flow: FlowTuple, // flow tuple identyfikujący połączenie
    pub ip_headers: IpHeaders, // Nagłówki IP
    pub transport: TransportHeaderOwned, // Nagłówek warstwy transportowej
    pub transport_offset: usize, // Offset nagłówka transportowego
    pub payload_offset: usize, // Offset payloadu
    pub payload_len: usize, // Długość payloadu
}

/// Parsuje flow tuple z ramki ethernetowej
pub(crate) fn parse_flow_tuple_from_ethernet(data: &[u8]) -> Option<FlowTuple> {
    let flow = parse_packet(data).map(|packet| packet.flow);
    
    tracing::trace!(packet_len = data.len(), ?flow, "nat parsed flow tuple from ethernet");
    
    flow
}

/// Zwraca adresy IP źródłowy i docelowy z ramki ethernetowej
pub(crate) fn packet_endpoints_from_ethernet(data: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let packet = SlicedPacket::from_ethernet(data).ok()?;

    let endpoints = match &packet.net {
        Some(NetSlice::Ipv4(ipv4)) => Some((
            IpAddr::V4(ipv4.header().source_addr()),
            IpAddr::V4(ipv4.header().destination_addr()),
        )),
        Some(NetSlice::Ipv6(ipv6)) => Some((
            IpAddr::V6(ipv6.header().source_addr()),
            IpAddr::V6(ipv6.header().destination_addr()),
        )),
        _ => None,
    };
    
    tracing::trace!(packet_len = data.len(), ?endpoints, "nat extracted packet endpoints");
    
    endpoints
}

/// Zwraca zakres bajtów payloadu warstwy transportowej
pub(crate) fn transport_payload_range(data: &[u8]) -> Option<Range<usize>> {
    let parsed = parse_packet(data)?;

    let range = parsed.payload_offset..parsed.payload_offset + parsed.payload_len;
    
    tracing::trace!(packet_len = data.len(), payload_range = ?range, "nat resolved transport payload range");
    
    Some(range)
}

/// Zmienia adresy i porty w pakiecie zgodnie z translacją NAT
pub(crate) fn apply_translation(
    data: &mut [u8],
    original: &FlowTuple,
    translated: &FlowTuple,
) -> bool {
    let parsed = match parse_packet(data) {
        Some(parsed) => parsed,
        None => {
            tracing::trace!("nat apply translation skipped: packet parse failed");
            return false;
        }
    };

    tracing::trace!(original = ?original, translated = ?translated, "nat applying packet translation");
    
    let mut ip_headers = parsed.ip_headers.clone();
    
    if !rewrite_network_addresses(&mut ip_headers, original, translated) {
        tracing::trace!(original = ?original, translated = ?translated, "nat apply translation rejected by ip family mismatch");
        return false;
    }

    let payload_range = parsed.payload_offset..parsed.payload_offset + parsed.payload_len;
    
    let payload = &data[payload_range.clone()];
    
    let transport_header_len = parsed.transport.header_len();

        match parsed.transport {
            TransportHeaderOwned::Tcp(mut tcp) => {
                rewrite_transport_ports_tcp(&mut tcp, original, translated);
                
                tcp.checksum = compute_tcp_checksum(&tcp, &ip_headers, payload);
                
                if !write_ip_headers(data, &mut ip_headers, transport_header_len + payload.len()) {
                    return false;
                }
                
                write_tcp_header(data, parsed.transport_offset, &tcp)
            }
            TransportHeaderOwned::Udp(mut udp) => {
                rewrite_transport_ports_udp(&mut udp, original, translated);
                
                udp.length = (UdpHeader::LEN + payload.len()) as u16;
                udp.checksum = compute_udp_checksum(&udp, &ip_headers, payload);
                
                if !write_ip_headers(data, &mut ip_headers, transport_header_len + payload.len()) {
                    return false;
                }
                
                write_udp_header(data, parsed.transport_offset, &udp)
            }
            TransportHeaderOwned::Icmp => {
                write_ip_headers(data, &mut ip_headers, payload.len())
            }
    }
}

/// Odświeża sumy kontrolne i długości po zmianie payloadu
pub(crate) fn refresh_after_payload_resize(data: &mut [u8]) -> bool {
    let parsed = match parse_packet(data) {
        Some(parsed) => parsed,
        None => {
            tracing::trace!("nat refresh after payload resize skipped: packet parse failed");
            return false;
        }
    };

    tracing::trace!(packet_len = data.len(), flow = ?parsed.flow, "nat refreshing packet after payload resize");
    
    let payload_range = parsed.payload_offset..parsed.payload_offset + parsed.payload_len;
    
    let payload = &data[payload_range.clone()];
    
    let mut ip_headers = parsed.ip_headers.clone();
    let transport_header_len = parsed.transport.header_len();

    match parsed.transport {
        TransportHeaderOwned::Tcp(mut tcp) => {
            tcp.checksum = compute_tcp_checksum(&tcp, &ip_headers, payload);
            
            if !write_ip_headers(data, &mut ip_headers, transport_header_len + payload.len()) {
                return false;
            }
            
            write_tcp_header(data, parsed.transport_offset, &tcp)
        }
        TransportHeaderOwned::Udp(mut udp) => {
            udp.length = (UdpHeader::LEN + payload.len()) as u16;
            udp.checksum = compute_udp_checksum(&udp, &ip_headers, payload);
            
            if !write_ip_headers(data, &mut ip_headers, transport_header_len + payload.len()) {
                return false;
            }
            
            write_udp_header(data, parsed.transport_offset, &udp)
        }
        TransportHeaderOwned::Icmp => write_ip_headers(data, &mut ip_headers, payload.len()),
    }
}

/// Parsuje pakiet i zwraca strukturę ParsedPacket
fn parse_packet(data: &[u8]) -> Option<ParsedPacket> {
    let packet = SlicedPacket::from_ethernet(data).ok()?;
    
    if packet.is_ip_payload_fragmented() {
        tracing::trace!("nat packet parsing skipped fragmented packet");
        return None;
    }

    let (src_ip, dst_ip) = match &packet.net {
        Some(NetSlice::Ipv4(ipv4)) => (
            IpAddr::V4(ipv4.header().source_addr()),
            IpAddr::V4(ipv4.header().destination_addr()),
        ),
        Some(NetSlice::Ipv6(ipv6)) => (
            IpAddr::V6(ipv6.header().source_addr()),
            IpAddr::V6(ipv6.header().destination_addr()),
        ),
        _ => return None,
    };

    let (ip_headers, ip_payload) = IpHeaders::from_slice(&data[ETH_HEADER_LEN..]).ok()?;
    
    let transport_offset = ETH_HEADER_LEN + ip_headers.header_len();

    let (proto, src_port, dst_port, transport, payload_len) = match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let (tcp_header, payload) = TcpHeader::from_slice(ip_payload.payload).ok()?;
            (
                L4Proto::Tcp,
                tcp.source_port(),
                tcp.destination_port(),
                TransportHeaderOwned::Tcp(tcp_header),
                payload.len(),
            )
        }
        Some(TransportSlice::Udp(udp)) => {
            let (udp_header, payload) = UdpHeader::from_slice(ip_payload.payload).ok()?;
            (
                L4Proto::Udp,
                udp.source_port(),
                udp.destination_port(),
                TransportHeaderOwned::Udp(udp_header),
                payload.len(),
            )
        }
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => (
            L4Proto::Icmp,
            0,
            0,
            TransportHeaderOwned::Icmp,
            ip_payload.payload.len(),
        ),
        _ => return None,
    };

    let transport_header_len = transport.header_len();
    
    let parsed = ParsedPacket {
        flow: FlowTuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        },
        ip_headers,
        transport,
        transport_offset,
        payload_offset: transport_offset + transport_header_len,
        payload_len,
    };
    
    tracing::trace!(flow = ?parsed.flow, payload_len = parsed.payload_len, "nat parsed packet metadata");
    
    Some(parsed)
}

/// Zmienia adresy IP w nagłówkach IP na przetłumaczone
fn rewrite_network_addresses(
    ip_headers: &mut IpHeaders,
    original: &FlowTuple,
    translated: &FlowTuple,
) -> bool {
    match ip_headers {
        IpHeaders::Ipv4(ipv4, _) => {
            if original.src_ip != translated.src_ip {
                let IpAddr::V4(src) = translated.src_ip else {
                    return false;
                };
                
                ipv4.source = src.octets();
            }
            if original.dst_ip != translated.dst_ip {
                let IpAddr::V4(dst) = translated.dst_ip else {
                    return false;
                };
                
                ipv4.destination = dst.octets();
            }
            true
        }
        IpHeaders::Ipv6(ipv6, _) => {
            if original.src_ip != translated.src_ip {
                let IpAddr::V6(src) = translated.src_ip else {
                    return false;
                };
                
                ipv6.source = src.octets();
            }
            if original.dst_ip != translated.dst_ip {
                let IpAddr::V6(dst) = translated.dst_ip else {
                    return false;
                };
                
                ipv6.destination = dst.octets();
            }
            true
        }
    }
}

/// Zmienia porty w nagłówku TCP na przetłumaczone
fn rewrite_transport_ports_tcp(
    header: &mut TcpHeader,
    original: &FlowTuple,
    translated: &FlowTuple,
) {
    if original.src_port != translated.src_port {
        header.source_port = translated.src_port;
    }
    
    if original.dst_port != translated.dst_port {
        header.destination_port = translated.dst_port;
    }
}

/// Zmienia porty w nagłówku UDP na przetłumaczone
fn rewrite_transport_ports_udp(
    header: &mut UdpHeader,
    original: &FlowTuple,
    translated: &FlowTuple,
) {
    if original.src_port != translated.src_port {
        header.source_port = translated.src_port;
    }
    
    if original.dst_port != translated.dst_port {
        header.destination_port = translated.dst_port;
    }
}

/// Oblicza sumę kontrolną TCP
fn compute_tcp_checksum(header: &TcpHeader, ip_headers: &IpHeaders, payload: &[u8]) -> u16 {
    match ip_headers {
        IpHeaders::Ipv4(ipv4, _) => header.calc_checksum_ipv4(ipv4, payload).ok().unwrap_or(0),
        IpHeaders::Ipv6(ipv6, _) => header.calc_checksum_ipv6(ipv6, payload).ok().unwrap_or(0),
    }
}

/// Oblicza sumę kontrolną UDP
fn compute_udp_checksum(header: &UdpHeader, ip_headers: &IpHeaders, payload: &[u8]) -> u16 {
    match ip_headers {
        IpHeaders::Ipv4(_, _) if header.checksum == 0 => 0,
        IpHeaders::Ipv4(ipv4, _) => header.calc_checksum_ipv4(ipv4, payload).ok().unwrap_or(0),
        IpHeaders::Ipv6(ipv6, _) => header.calc_checksum_ipv6(ipv6, payload).ok().unwrap_or(0),
    }
}

/// Zapisuje nagłówki IP do bufora pakietu
fn write_ip_headers(data: &mut [u8], ip_headers: &mut IpHeaders, transport_len: usize) -> bool {
    if ip_headers.set_payload_len(transport_len).is_err() {
        tracing::warn!(transport_len, "nat failed to update ip payload length");
        return false;
    }

    if let IpHeaders::Ipv4(ipv4, _) = ip_headers {
        ipv4.header_checksum = ipv4.calc_header_checksum();
    }

    let header_len = ip_headers.header_len();
    
    if data.len() < ETH_HEADER_LEN + header_len {
        tracing::warn!(buffer_len = data.len(), header_len, "nat failed to write ip headers: buffer too short");
        return false;
    }

    let written = ip_headers
        .write(&mut Cursor::new(&mut data[ETH_HEADER_LEN..ETH_HEADER_LEN + header_len]))
        .is_ok();
    
    if !written {
        tracing::warn!("nat failed to serialize ip headers");
    }
    
    written
}

/// Zapisuje nagłówek TCP do bufora pakietu
fn write_tcp_header(data: &mut [u8], transport_offset: usize, tcp: &TcpHeader) -> bool {
    let header_len = tcp.header_len();
    
    if data.len() < transport_offset + header_len {
        tracing::warn!(buffer_len = data.len(), transport_offset, header_len, "nat failed to write tcp header: buffer too short");
        return false;
    }

    let written = tcp.write(&mut Cursor::new(
        &mut data[transport_offset..transport_offset + header_len],
    )).is_ok();
    
    if !written {
        tracing::warn!("nat failed to serialize tcp header");
    }
    
    written
}

/// Zapisuje nagłówek UDP do bufora pakietu
fn write_udp_header(data: &mut [u8], transport_offset: usize, udp: &UdpHeader) -> bool {
    if data.len() < transport_offset + UdpHeader::LEN {
        tracing::warn!(buffer_len = data.len(), transport_offset, header_len = UdpHeader::LEN, "nat failed to write udp header: buffer too short");
        return false;
    }

    let written = udp.write(&mut Cursor::new(
        &mut data[transport_offset..transport_offset + UdpHeader::LEN],
    )).is_ok();
    
    if !written {
        tracing::warn!("nat failed to serialize udp header");
    }
    
    written
}

/// Sprawdza czy oba adresy IP są tego samego typu (IPv4/IPv6)
pub(crate) fn same_ip_family(lhs: IpAddr, rhs: IpAddr) -> bool {
    matches!(
        (lhs, rhs),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}
