//! Cross-language contract test for `flow_id_for`.
//!
//! Locks the byte-level output to the values computed in Python via
//! `hashlib.blake2b(raw, digest_size=8)`. If either side changes its
//! canonicalization (lex order, formatting, keying), train/test splits
//! will silently drift; this test makes that drift a compile-time error.

use std::net::{IpAddr, Ipv4Addr};

use raptorgate_pcap::flow_id::flow_id_for;

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
