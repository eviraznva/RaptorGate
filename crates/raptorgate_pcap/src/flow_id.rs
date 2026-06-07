use std::net::IpAddr;

use blake2::digest::consts::U8;
use blake2::{Blake2b, Digest};

pub fn flow_id_for(proto: u8, src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> u64 {
    let left = (src_ip, src_port);
    let right = (dst_ip, dst_port);
    let (lo, hi) = if right < left { (right, left) } else { (left, right) };

    let s = format!("{proto}|{}|{}|{}|{}", lo.0, lo.1, hi.0, hi.1);
    let mut hasher: Blake2b<U8> = Blake2b::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    let bytes: [u8; 8] = result[..8].try_into().expect("Blake2b<U8> produces 8 bytes");
    u64::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn canonical_canonicalizes_both_directions() {
        let a = flow_id_for(
            6,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        let b = flow_id_for(
            6,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn matches_python_tcp_v4_443() {
        let v = flow_id_for(
            6,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        );
        assert_eq!(v, 17817171399609386574);
    }

    #[test]
    fn matches_python_udp_v4() {
        let v = flow_id_for(
            17,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            53,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            33333,
        );
        assert_eq!(v, 15168991421379642141);
    }

    #[test]
    fn matches_python_v4_edge() {
        let v = flow_id_for(
            1,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            0,
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            65535,
        );
        assert_eq!(v, 15444816644772025306);
    }
}
