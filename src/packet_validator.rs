use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum InvalidReason {
    #[error("TTL is zero")]
    TtlZero,
    #[error("invalid IPv4 header checksum")]
    BadIpv4Checksum,
    #[error("invalid TCP checksum")]
    BadTcpChecksum,
    #[error("invalid UDP checksum")]
    BadUdpChecksum,
    #[error("malformed packet (checksum could not be computed)")]
    MalformedPacket,
}

// Sprawdza czy pakiet jest poprawny: TTL, suma kontrolna IPv4 i L4.
pub(crate) fn validate(packet: &SlicedPacket) -> Result<(), InvalidReason> {
    let ipv4 = match &packet.net {
        Some(NetSlice::Ipv4(ipv4)) => ipv4,
        _ => return Ok(()),
    };

    let ip_header = ipv4.header().to_header();

    if ip_header.time_to_live == 0 {
        return Err(InvalidReason::TtlZero);
    }

    if ip_header.calc_header_checksum() != ip_header.header_checksum {
        return Err(InvalidReason::BadIpv4Checksum);
    }

    if packet.is_ip_payload_fragmented() {
        return Ok(());
    }

    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let tcp_header = tcp.to_header();
            match tcp_header.calc_checksum_ipv4(&ip_header, tcp.payload()) {
                Ok(expected) if expected != tcp_header.checksum => {
                    return Err(InvalidReason::BadTcpChecksum);
                }
                Err(_) => return Err(InvalidReason::MalformedPacket),
                _ => {}
            }
        }
        Some(TransportSlice::Udp(udp)) => {
            let udp_header = udp.to_header();
            if udp_header.checksum != 0 {
                match udp_header.calc_checksum_ipv4(&ip_header, udp.payload()) {
                    Ok(expected) if expected != udp_header.checksum => {
                        return Err(InvalidReason::BadUdpChecksum);
                    }
                    Err(_) => return Err(InvalidReason::MalformedPacket),
                    _ => {}
                }
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{PacketBuilder, SlicedPacket};

    fn build_tcp_packet(src: [u8; 4], dst: [u8; 4], ttl: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4(src, dst, ttl)
            .tcp(12345, 80, 1, 65535)
            .write(&mut buf, b"hello")
            .unwrap();
        buf
    }

    fn build_udp_packet(src: [u8; 4], dst: [u8; 4], ttl: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4(src, dst, ttl)
            .udp(54321, 53)
            .write(&mut buf, b"query")
            .unwrap();
        buf
    }

    // Przelicza checksumę IPv4 po modyfikacji bajtów.
    fn fix_ipv4_checksum(buf: &mut [u8]) {
        buf[24] = 0;
        buf[25] = 0;
        let mut sum: u32 = 0;
        for i in (14..34).step_by(2) {
            sum += ((buf[i] as u32) << 8) | buf[i + 1] as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        buf[24] = (cksum >> 8) as u8;
        buf[25] = (cksum & 0xFF) as u8;
    }

    // Sprawdza czy pakiet TCP jest poprawny.
    #[test]
    fn valid_tcp_packet_passes() {
        let buf = build_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 64);
        let packet = SlicedPacket::from_ethernet(&buf).unwrap();
        assert!(validate(&packet).is_ok());
    }

    // Sprawdza czy pakiet UDP jest poprawny.
    #[test]
    fn valid_udp_packet_passes() {
        let buf = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 64);
        let packet = SlicedPacket::from_ethernet(&buf).unwrap();
        assert!(validate(&packet).is_ok());
    }

    // Sprawdza czy pakiet z TTL=0 jest odrzucony.
    #[test]
    fn ttl_zero_rejected() {
        let buf = build_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 0);
        let packet = SlicedPacket::from_ethernet(&buf).unwrap();
        assert!(matches!(validate(&packet), Err(InvalidReason::TtlZero)));
    }

    // Sprawdza czy pakiet z zepsuta checksuma IPv4 jest odrzucony.
    #[test]
    fn bad_ipv4_checksum_rejected() {
        let mut buf = build_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 64);
        buf[24] ^= 0xFF;
        let packet = SlicedPacket::from_ethernet(&buf).unwrap();
        assert!(matches!(
            validate(&packet),
            Err(InvalidReason::BadIpv4Checksum)
        ));
    }

    // Sprawdza czy pakiet z zepsutą sumą kontrolną TCP jest odrzucony.
    #[test]
    fn bad_tcp_checksum_rejected() {
        let mut buf = build_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 64);
        buf[50] ^= 0xFF;
        let packet = SlicedPacket::from_ethernet(&buf).unwrap();
        assert!(matches!(
            validate(&packet),
            Err(InvalidReason::BadTcpChecksum)
        ));
    }

    // Sprawdza czy pakiet z zepsutą sumą kontrolną UDP jest odrzucony.
    #[test]
    fn bad_udp_checksum_rejected() {
        let mut buf = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 64);
        buf[40] ^= 0xFF;
        let packet = SlicedPacket::from_ethernet(&buf).unwrap();
        assert!(matches!(
            validate(&packet),
            Err(InvalidReason::BadUdpChecksum)
        ));
    }

    // Sprawdza czy pakiet UDP z sumą kontrolną = 0 przechodzi.
    #[test]
    fn udp_zero_checksum_passes() {
        let mut buf = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 64);
        buf[40] = 0;
        buf[41] = 0;
        let packet = SlicedPacket::from_ethernet(&buf).unwrap();
        assert!(validate(&packet).is_ok());
    }

    // Sprawdza czy fragmentowany pakiet omija walidacje L4 (walidacja L4 następuje po złożeniu przez ip_defrag)
    #[test]
    fn fragmented_packet_passes_validation() {
        let mut buf = build_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 64);
        buf[20] |= 0x20;
        fix_ipv4_checksum(&mut buf);
        let packet = SlicedPacket::from_ethernet(&buf).unwrap();
        assert!(packet.is_ip_payload_fragmented());
        assert!(validate(&packet).is_ok());
    }

    // Sprawdza czy nie ma błędu przy pomijaniu pakietów nie ipv4.
    #[test]
    fn non_ipv4_packet_passes() {
        let mut buf = build_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 64);
        buf[12] = 0x08;
        buf[13] = 0x06;
        if let Ok(packet) = SlicedPacket::from_ethernet(&buf) {
            if packet.net.is_none() {
                assert!(validate(&packet).is_ok());
            }
        }
    }
}
