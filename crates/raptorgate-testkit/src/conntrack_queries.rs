use std::net::{IpAddr, Ipv4Addr};

use ngfw::conntrack::entry::CtInfo;
use ngfw::conntrack::table::ConntrackFlowSnapshot;

pub trait ConntrackSnapshotExt {
    fn flow_count(&self) -> usize;
    fn contains_flow_ipv4(&self, a: [u8; 4], b: [u8; 4]) -> bool;
    fn established_flow_count(&self) -> usize;
}

impl ConntrackSnapshotExt for [ConntrackFlowSnapshot] {
    fn flow_count(&self) -> usize {
        self.len()
    }

    fn contains_flow_ipv4(&self, a: [u8; 4], b: [u8; 4]) -> bool {
        let a = IpAddr::V4(Ipv4Addr::from(a));
        let b = IpAddr::V4(Ipv4Addr::from(b));
        self.iter().any(|f| {
            let o = &f.original;
            (o.src_ip == a && o.dst_ip == b) || (o.src_ip == b && o.dst_ip == a)
        })
    }

    fn established_flow_count(&self) -> usize {
        self.iter()
            .filter(|f| matches!(f.state, CtInfo::Established))
            .count()
    }
}

impl ConntrackSnapshotExt for Vec<ConntrackFlowSnapshot> {
    fn flow_count(&self) -> usize {
        self.as_slice().flow_count()
    }

    fn contains_flow_ipv4(&self, a: [u8; 4], b: [u8; 4]) -> bool {
        self.as_slice().contains_flow_ipv4(a, b)
    }

    fn established_flow_count(&self) -> usize {
        self.as_slice().established_flow_count()
    }
}
