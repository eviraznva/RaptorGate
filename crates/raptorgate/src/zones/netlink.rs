use std::collections::HashMap;

use dashmap::DashMap;
use futures::TryStreamExt;
use ipnet::IpNet;
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{
        InfoData as LinkInfoData,
        InfoVlan,
        LinkAttribute,
        LinkInfo,
        LinkMessage,
        State as LinkState,
    },
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkInterfaceMonitorError {
    #[error("failed to open netlink connection")]
    Connection(#[source] std::io::Error),
    #[error("failed to read link dump from netlink")]
    LinkDump(#[source] rtnetlink::Error),
    #[error("failed to read address dump from netlink")]
    AddressDump(#[source] rtnetlink::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperState {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInterface {
    pub index: u32,
    pub name: String,
    pub oper_state: OperState,
    pub addresses: Vec<IpNet>,
    pub vlan_id: Option<u16>,
}

#[cfg_attr(test, mockall::automock)]
pub trait InterfaceMonitor: Send + Sync {
    fn get(&self, name: &str) -> Option<SystemInterface>;
    fn snapshot(&self) -> HashMap<String, SystemInterface>;
}

pub struct NetworkInterfaceMonitor {
    interfaces: DashMap<String, SystemInterface>,
}

impl NetworkInterfaceMonitor {
    pub async fn new() -> Result<Self, NetworkInterfaceMonitorError> {
        let (connection, handle, _) =
            rtnetlink::new_connection().map_err(NetworkInterfaceMonitorError::Connection)?;
        tokio::spawn(connection);

        let mut interfaces_by_index = HashMap::new();
        let mut links = handle.link().get().execute();

        while let Some(link) = links
            .try_next()
            .await
            .map_err(NetworkInterfaceMonitorError::LinkDump)?
        {
            if let Some(parsed) = parse_link(link) {
                interfaces_by_index.insert(parsed.index, parsed);
            }
        }

        let mut addresses = handle.address().get().execute();
        while let Some(address) = addresses
            .try_next()
            .await
            .map_err(NetworkInterfaceMonitorError::AddressDump)?
        {
            if let Some(parsed) = parse_address(&address)
                && let Some(interface) = interfaces_by_index.get_mut(&address.header.index)
                    && !interface.addresses.contains(&parsed) {
                        interface.addresses.push(parsed);
                    }
        }

        let interfaces = DashMap::new();
        for interface in interfaces_by_index.into_values() {
            interfaces.insert(interface.name.clone(), interface);
        }

        Ok(Self { interfaces })
    }
}

impl InterfaceMonitor for NetworkInterfaceMonitor {
    fn get(&self, name: &str) -> Option<SystemInterface> {
        self.interfaces.get(name).map(|entry| entry.value().clone())
    }

    fn snapshot(&self) -> HashMap<String, SystemInterface> {
        self.interfaces
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }
}

fn parse_link(message: LinkMessage) -> Option<SystemInterface> {
    let name = message.attributes.iter().find_map(link_name)?;
    let oper_state = message
        .attributes
        .iter()
        .find_map(link_oper_state)
        .unwrap_or(OperState::Unknown);
    let vlan_id = message.attributes.iter().find_map(link_vlan_id);

    Some(SystemInterface {
        index: message.header.index,
        name,
        oper_state,
        addresses: Vec::new(),
        vlan_id,
    })
}

fn parse_address(message: &AddressMessage) -> Option<IpNet> {
    let prefix_len = message.header.prefix_len;
    message
        .attributes
        .iter()
        .find_map(address_ip)
        .and_then(|ip| IpNet::new(ip, prefix_len).ok())
}

fn link_name(attribute: &LinkAttribute) -> Option<String> {
    match attribute {
        LinkAttribute::IfName(name) => Some(name.clone()),
        _ => None,
    }
}

fn link_oper_state(attribute: &LinkAttribute) -> Option<OperState> {
    match attribute {
        LinkAttribute::OperState(state) => Some(match state {
            LinkState::Up => OperState::Up,
            LinkState::Down => OperState::Down,
            _ => OperState::Unknown,
        }),
        _ => None,
    }
}

fn link_vlan_id(attribute: &LinkAttribute) -> Option<u16> {
    let LinkAttribute::LinkInfo(info_items) = attribute else {
        return None;
    };

    for item in info_items {
        if let LinkInfo::Data(data) = item {
            if let LinkInfoData::Vlan(vlan_data) = data {
                for vlan_item in vlan_data {
                    if let InfoVlan::Id(vlan_id) = vlan_item {
                        return Some(*vlan_id);
                    }
                }
            }
        }
    }

    None
}

fn address_ip(attribute: &AddressAttribute) -> Option<std::net::IpAddr> {
    match attribute {
        AddressAttribute::Local(ip) | AddressAttribute::Address(ip) => Some(*ip),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ipnet::IpNet;
    use mockall::predicate::eq;

    use super::{InterfaceMonitor, MockInterfaceMonitor, OperState, SystemInterface};

    #[test]
    fn mock_interface_monitor_get_contract() {
        let mut monitor = MockInterfaceMonitor::new();
        let expected = SystemInterface {
            index: 2,
            name: "eth0".to_string(),
            oper_state: OperState::Up,
            addresses: vec!["192.168.10.10/24".parse::<IpNet>().expect("valid CIDR")],
            vlan_id: Some(100),
        };

        monitor
            .expect_get()
            .with(eq("eth0"))
            .times(1)
            .return_once(move |_| Some(expected));

        let result = monitor.get("eth0");
        assert!(result.is_some());
        assert_eq!(result.expect("interface exists").oper_state, OperState::Up);
    }

    #[test]
    fn mock_interface_monitor_snapshot_contract() {
        let mut monitor = MockInterfaceMonitor::new();

        monitor.expect_snapshot().times(1).return_once(|| {
            HashMap::from([(
                "eth1".to_string(),
                SystemInterface {
                    index: 3,
                    name: "eth1".to_string(),
                    oper_state: OperState::Down,
                    addresses: vec![],
                    vlan_id: None,
                },
            )])
        });

        let snapshot = monitor.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot.get("eth1").expect("eth1 present").oper_state, OperState::Down);
    }
}
