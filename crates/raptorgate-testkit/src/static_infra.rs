use std::collections::HashMap;
use std::sync::Arc;

use ipnet::IpNet;
use ngfw::interfaces::{NetworkInterfaceMonitor, OperState, SystemInterface, SystemInterfaceId};

pub fn iface_eth(
    name: &'static str,
    index: u32,
    cidr: &str,
) -> (String, SystemInterface) {
    let net: IpNet = cidr.parse().expect("cidr");
    (
        name.to_string(),
        SystemInterface {
            index: SystemInterfaceId::from(index),
            name: name.to_string(),
            oper_state: OperState::Up,
            addresses: vec![net],
            vlan_id: None,
        },
    )
}

pub fn static_monitor_from_pairs(pairs: impl IntoIterator<Item = (String, SystemInterface)>) -> Arc<NetworkInterfaceMonitor> {
    Arc::new(NetworkInterfaceMonitor::from_static_interfaces(HashMap::from_iter(
        pairs,
    )))
}
