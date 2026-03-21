use std::net::IpAddr;

use crate::data_plane::nat::types::port_range_dummy::PortRangeDummy;

#[derive(Debug, Clone)]
pub enum NatKindDummy {
    Snat {
        to_addr: IpAddr,
    },
    Masquerade {
        interface: String,
        port_pool: Option<PortRangeDummy>,
    },
    Dnat {
        to_addr: IpAddr,
        to_port: Option<u16>,
    },
    Pat {
        to_addr: Option<IpAddr>,
        interface: Option<String>,
        port_pool: PortRangeDummy,
    },
}