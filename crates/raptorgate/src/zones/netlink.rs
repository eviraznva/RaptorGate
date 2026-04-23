use std::collections::HashMap;

use dashmap::DashMap;
use futures::stream::StreamExt;
use futures::TryStreamExt;
use ipnet::IpNet;
use netlink_packet_route::RouteNetlinkMessage;
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
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::NetlinkPayload;
use thiserror::Error;
use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::events::{self, Event, EventKind};

#[derive(Debug, Error)]
pub enum NetworkInterfaceMonitorError {
    #[error("failed to open netlink connection")]
    Connection(#[source] std::io::Error),
    #[error("failed to read link dump from netlink")]
    LinkDump(#[source] rtnetlink::Error),
    #[error("failed to read address dump from netlink")]
    AddressDump(#[source] rtnetlink::Error),
    #[error("failed to open netlink multicast connection")]
    MulticastConnection(#[source] std::io::Error),
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
    pub async fn new(cancel: CancellationToken) -> Result<Self, NetworkInterfaceMonitorError> {
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

        let monitor = Self { interfaces };
        monitor.spawn_live_updates(cancel)?;
        Ok(monitor)
    }

    fn spawn_live_updates(&self, cancel: CancellationToken) -> Result<(), NetworkInterfaceMonitorError> {
        let groups = [
            MulticastGroup::Link,
            MulticastGroup::Ipv4Ifaddr,
            MulticastGroup::Ipv6Ifaddr,
        ];
        let (connection, _handle, mut messages) = rtnetlink::new_multicast_connection(&groups)
            .map_err(NetworkInterfaceMonitorError::MulticastConnection)?;
        let interfaces = self.interfaces.clone();

        tokio::spawn(connection);

        tokio::spawn(async move {
            loop {
                select! {
                    _ = cancel.cancelled() => {
                        break;
                    }
                    msg = messages.next() => {
                        let Some((message, _addr)) = msg else {
                            break;
                        };

                        if let NetlinkPayload::InnerMessage(inner) = message.payload {
                            handle_route_message(&interfaces, inner);
                        }
                    }
                }
            }
        });

        Ok(())
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

fn handle_route_message(interfaces: &DashMap<String, SystemInterface>, message: RouteNetlinkMessage) {
    match message {
        RouteNetlinkMessage::NewLink(link) => {
            if let Some(new_interface) = parse_link(link) {
                upsert_link(interfaces, new_interface);
            }
        }
        RouteNetlinkMessage::DelLink(link) => {
            remove_link(interfaces, link);
        }
        RouteNetlinkMessage::NewAddress(address) => {
            apply_address_change(interfaces, address, true);
        }
        RouteNetlinkMessage::DelAddress(address) => {
            apply_address_change(interfaces, address, false);
        }
        _ => {}
    }
}

fn upsert_link(interfaces: &DashMap<String, SystemInterface>, mut new_interface: SystemInterface) {
    let mut old_for_state = None;

    if let Some((old_name, old_interface)) = find_by_index(interfaces, new_interface.index)
        && old_name != new_interface.name
    {
        interfaces.remove(&old_name);
        new_interface.addresses = old_interface.addresses.clone();
        emit_rename_event(new_interface.index, &old_name, &new_interface.name, &new_interface);
        old_for_state = Some(old_interface);
    }

    if old_for_state.is_none()
        && let Some(existing) = interfaces.get(&new_interface.name)
    {
        new_interface.addresses = existing.addresses.clone();
    }

    let replaced = interfaces.insert(new_interface.name.clone(), new_interface.clone());
    if old_for_state.is_none() {
        old_for_state = replaced.filter(|old| old.index == new_interface.index);
    }

    maybe_emit_state_event(old_for_state.as_ref(), Some(&new_interface));
}

fn remove_link(interfaces: &DashMap<String, SystemInterface>, link: LinkMessage) {
    let old = interfaces
        .iter()
        .find(|entry| entry.value().index == link.header.index)
        .map(|entry| entry.key().clone())
        .and_then(|name| interfaces.remove(&name).map(|(_, value)| value));
    maybe_emit_state_event(old.as_ref(), None);
}

fn apply_address_change(interfaces: &DashMap<String, SystemInterface>, address: AddressMessage, add: bool) {
    let Some(parsed) = parse_address(&address) else {
        return;
    };

    let Some((name, mut interface)) = find_by_index(interfaces, address.header.index) else {
        return;
    };

    let old = interface.clone();

    if add {
        if !interface.addresses.contains(&parsed) {
            interface.addresses.push(parsed);
        }
    } else {
        interface.addresses.retain(|ip| ip != &parsed);
    }

    interfaces.insert(name, interface.clone());
    maybe_emit_state_event(Some(&old), Some(&interface));
}

fn find_by_index(interfaces: &DashMap<String, SystemInterface>, index: u32) -> Option<(String, SystemInterface)> {
    interfaces
        .iter()
        .find(|entry| entry.value().index == index)
        .map(|entry| (entry.key().clone(), entry.value().clone()))
}

fn normalize_addresses(addresses: &[IpNet]) -> Vec<String> {
    let mut values: Vec<String> = addresses.iter().map(ToString::to_string).collect();
    values.sort();
    values
}

fn status_from_interface(interface: Option<&SystemInterface>) -> &'static str {
    match interface {
        None => "missing",
        Some(item) => match item.oper_state {
            OperState::Up => "active",
            OperState::Down => "inactive",
            OperState::Unknown => "unknown",
        },
    }
}

fn maybe_emit_state_event(old: Option<&SystemInterface>, new: Option<&SystemInterface>) {
    let old_status = status_from_interface(old);
    let new_status = status_from_interface(new);
    let old_addresses = old.map_or_else(Vec::new, |item| normalize_addresses(&item.addresses));
    let new_addresses = new.map_or_else(Vec::new, |item| normalize_addresses(&item.addresses));

    if old_status == new_status && old_addresses == new_addresses {
        return;
    }

    let interface_name = new
        .map(|item| item.name.clone())
        .or_else(|| old.map(|item| item.name.clone()));

    if let Some(interface_name) = interface_name {
        events::emit(Event::new(EventKind::InterfaceStateChanged {
            interface_name,
            old_status: old_status.to_string(),
            new_status: new_status.to_string(),
            addresses: new_addresses,
        }));
    }
}

fn emit_rename_event(interface_index: u32, old_name: &str, new_name: &str, current: &SystemInterface) {
    events::emit(Event::new(EventKind::InterfaceRenamed {
        interface_index,
        old_interface_name: old_name.to_string(),
        new_interface_name: new_name.to_string(),
        status: status_from_interface(Some(current)).to_string(),
        addresses: normalize_addresses(&current.addresses),
    }));
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

    #[test]
    fn normalize_addresses_sorts_output() {
        let addresses = vec![
            "2001:db8::1/64".parse::<IpNet>().expect("valid ipv6"),
            "10.0.0.5/24".parse::<IpNet>().expect("valid ipv4"),
            "10.0.0.1/24".parse::<IpNet>().expect("valid ipv4"),
        ];

        let normalized = super::normalize_addresses(&addresses);
        assert_eq!(
            normalized,
            vec![
                "10.0.0.1/24".to_string(),
                "10.0.0.5/24".to_string(),
                "2001:db8::1/64".to_string(),
            ]
        );
    }

    #[test]
    fn status_from_interface_maps_oper_states() {
        let up = SystemInterface {
            index: 1,
            name: "eth1".to_string(),
            oper_state: OperState::Up,
            addresses: vec![],
            vlan_id: None,
        };
        let down = SystemInterface {
            oper_state: OperState::Down,
            ..up.clone()
        };
        let unknown = SystemInterface {
            oper_state: OperState::Unknown,
            ..up.clone()
        };

        assert_eq!(super::status_from_interface(None), "missing");
        assert_eq!(super::status_from_interface(Some(&up)), "active");
        assert_eq!(super::status_from_interface(Some(&down)), "inactive");
        assert_eq!(super::status_from_interface(Some(&unknown)), "unknown");
    }
}
