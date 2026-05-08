use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use derive_more::{Display, From, Into};
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
use thiserror::Error;
use tokio::select;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::events::{self, Event, EventKind};
use crate::netlink::listener::NetlinkListener;

#[derive(Debug, Error)]
pub enum NetworkInterfaceMonitorError {
    #[error("failed to open netlink connection")]
    Connection(#[source] std::io::Error),
    #[error("failed to read link dump from netlink")]
    LinkDump(#[source] rtnetlink::Error),
    #[error("failed to read address dump from netlink")]
    AddressDump(#[source] rtnetlink::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, Hash, From, Into)]
pub struct SystemInterfaceId(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum OperState {
    #[display("active")]
    Up,
    #[display("inactive")]
    Down,
    #[display("unknown")]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInterface {
    pub index: SystemInterfaceId,
    pub name: String,
    pub oper_state: OperState,
    pub addresses: Vec<IpNet>,
    pub vlan_id: Option<u16>,
}

#[cfg_attr(test, mockall::automock)]
pub trait InterfaceMonitor: Send + Sync {
    fn get(&self, name: &str) -> Option<SystemInterface>;
    fn get_by_index(&self, index: SystemInterfaceId) -> Option<SystemInterface>;
    fn snapshot(&self) -> HashMap<String, SystemInterface>;
}

#[derive(Clone)]
pub struct NetworkInterfaceMonitor {
    interfaces: Arc<DashMap<String, SystemInterface>>,
}

impl NetworkInterfaceMonitor {
    pub async fn new(
        cancel: CancellationToken,
        listener: &NetlinkListener,
    ) -> Result<Self, NetworkInterfaceMonitorError> {
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
            if let Some(parsed) = parse_link(&link) {
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
                && let Some(interface) = interfaces_by_index.get_mut(&SystemInterfaceId::from(address.header.index))
                    && !interface.addresses.contains(&parsed) {
                        interface.addresses.push(parsed);
                    }
        }

        let interfaces = DashMap::new();
        for interface in interfaces_by_index.into_values() {
            interfaces.insert(interface.name.clone(), interface);
        }

        let monitor = Self { interfaces: Arc::new(interfaces) };
        monitor.spawn_live_updates(cancel, listener);
        Ok(monitor)
    }

    fn spawn_live_updates(&self, cancel: CancellationToken, listener: &NetlinkListener) {
        let mut rx = listener.subscribe();
        let monitor = self.clone();

        tokio::spawn(async move {
            loop {
                select! {
                    _ = cancel.cancelled() => {
                        break;
                    }
                    msg = rx.recv() => {
                        match msg {
                            Ok(inner) => {
                                monitor.handle_route_message(inner);
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!(missed_messages = n, "NetworkInterfaceMonitor subscriber lagged");
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                tracing::error!("NetlinkListener broadcast channel closed, monitor stopping live updates");
                                break;
                            }
                        }
                    }
                }
            }
        });
    }
}

impl InterfaceMonitor for NetworkInterfaceMonitor {
    fn get(&self, name: &str) -> Option<SystemInterface> {
        self.interfaces.get(name).map(|entry| entry.value().clone())
    }

    fn get_by_index(&self, index: SystemInterfaceId) -> Option<SystemInterface> {
        self.find_by_index(index).map(|(_, interface)| interface)
    }

    fn snapshot(&self) -> HashMap<String, SystemInterface> {
        self.interfaces
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }
}

impl NetworkInterfaceMonitor {
    fn handle_route_message(&self, message: RouteNetlinkMessage) {
        match message {
            RouteNetlinkMessage::NewLink(link) => {
                if let Some(new_interface) = parse_link(&link) {
                    self.upsert_link(new_interface);
                }
            }
            RouteNetlinkMessage::DelLink(link) => {
                self.remove_link(&link);
            }
            RouteNetlinkMessage::NewAddress(address) => {
                self.apply_address_change(address, true);
            }
            RouteNetlinkMessage::DelAddress(address) => {
                self.apply_address_change(address, false);
            }
            _ => {}
        }
    }

    fn upsert_link(&self, mut new_interface: SystemInterface) {
        let mut old_for_state = None;

        if let Some((old_name, old_interface)) = self.find_by_index(new_interface.index)
            && old_name != new_interface.name {
            self.interfaces.remove(&old_name);
            new_interface.addresses.clone_from(&old_interface.addresses);
            self.emit_rename_event(new_interface.index, &old_name, &new_interface.name, &new_interface);
            old_for_state = Some(old_interface);
        }

        if old_for_state.is_none()
            && let Some(existing) = self.interfaces.get(&new_interface.name) {
            new_interface.addresses = existing.addresses.clone();
        }

        let replaced = self.interfaces.insert(new_interface.name.clone(), new_interface.clone());
        if old_for_state.is_none() {
            old_for_state = replaced.filter(|old| old.index == new_interface.index);
        }

        self.maybe_emit_state_event(old_for_state.as_ref(), Some(&new_interface));
    }

    fn remove_link(&self, link: &LinkMessage) {
        let index = SystemInterfaceId::from(link.header.index);
        if let Some((name, interface)) = self.find_by_index(index) {
            self.interfaces.remove(&name);
            self.maybe_emit_state_event(Some(&interface), None);
        }
    }

    fn apply_address_change(&self, address: AddressMessage, add: bool) {
        let Some(parsed) = parse_address(&address) else {
            return;
        };

        let Some((name, mut interface)) = self.find_by_index(SystemInterfaceId::from(address.header.index)) else {
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

        self.interfaces.insert(name, interface.clone());
        self.maybe_emit_state_event(Some(&old), Some(&interface));
    }

    fn find_by_index(&self, index: SystemInterfaceId) -> Option<(String, SystemInterface)> {
        self.interfaces
            .iter()
            .find(|entry| entry.value().index == index)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
    }

    fn normalize_addresses(addresses: &[IpNet]) -> Vec<String> {
        let mut values: Vec<String> = addresses.iter().map(ToString::to_string).collect();
        values.sort();
        values
    }

    fn status_from_interface(interface: Option<&SystemInterface>) -> String {
        match interface {
            None => "missing".to_string(),
            Some(item) => item.oper_state.to_string(),
        }
    }

    fn maybe_emit_state_event(&self, old: Option<&SystemInterface>, new: Option<&SystemInterface>) {
        let old_status = Self::status_from_interface(old);
        let new_status = Self::status_from_interface(new);
        let old_addresses = old.map_or_else(Vec::new, |item| Self::normalize_addresses(&item.addresses));
        let new_addresses = new.map_or_else(Vec::new, |item| Self::normalize_addresses(&item.addresses));

        if old_status == new_status && old_addresses == new_addresses {
            return;
        }

        let interface_name = new
            .map(|item| item.name.clone())
            .or_else(|| old.map(|item| item.name.clone()));

        if let Some(interface_name) = interface_name {
            events::emit(Event::new(EventKind::InterfaceStateChanged {
                interface_name,
                old_status,
                new_status,
                addresses: new_addresses,
            }));
        }
    }

    fn emit_rename_event(&self, interface_index: SystemInterfaceId, old_name: &str, new_name: &str, current: &SystemInterface) {
        events::emit(Event::new(EventKind::InterfaceRenamed {
            interface_index: interface_index.into(),
            old_interface_name: old_name.to_string(),
            new_interface_name: new_name.to_string(),
            status: Self::status_from_interface(Some(current)),
            addresses: Self::normalize_addresses(&current.addresses),
        }));
    }
}

fn parse_link(message: &LinkMessage) -> Option<SystemInterface> {
    let name = message.attributes.iter().find_map(link_name)?;
    let oper_state = message
        .attributes
        .iter()
        .find_map(link_oper_state)
        .unwrap_or(OperState::Unknown);
    let vlan_id = message.attributes.iter().find_map(link_vlan_id);

    Some(SystemInterface {
        index: message.header.index.into(),
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
        if let LinkInfo::Data(data) = item
            && let LinkInfoData::Vlan(vlan_data) = data {
                for vlan_item in vlan_data {
                    if let InfoVlan::Id(vlan_id) = vlan_item {
                        return Some(*vlan_id);
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

    use super::{InterfaceMonitor, MockInterfaceMonitor, NetworkInterfaceMonitor, OperState, SystemInterface, SystemInterfaceId};

    #[test]
    fn mock_interface_monitor_get_contract() {
        let mut monitor = MockInterfaceMonitor::new();
        let expected = SystemInterface {
            index: SystemInterfaceId::from(2),
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
    fn mock_interface_monitor_get_by_index_contract() {
        let mut monitor = MockInterfaceMonitor::new();
        let expected = SystemInterface {
            index: SystemInterfaceId::from(2),
            name: "eth0".to_string(),
            oper_state: OperState::Up,
            addresses: vec![],
            vlan_id: None,
        };

        monitor
            .expect_get_by_index()
            .with(eq(SystemInterfaceId::from(2)))
            .times(1)
            .return_once(move |_| Some(expected));

        let result = monitor.get_by_index(SystemInterfaceId::from(2));
        assert!(result.is_some());
        assert_eq!(result.expect("interface exists").index, SystemInterfaceId::from(2));
    }

    #[test]
    fn mock_interface_monitor_snapshot_contract() {
        let mut monitor = MockInterfaceMonitor::new();

        monitor.expect_snapshot().times(1).return_once(|| {
            HashMap::from([(
                "eth1".to_string(),
                SystemInterface {
                    index: SystemInterfaceId::from(3),
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

        let normalized = NetworkInterfaceMonitor::normalize_addresses(&addresses);
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
            index: SystemInterfaceId::from(1),
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

        assert_eq!(NetworkInterfaceMonitor::status_from_interface(None), "missing");
        assert_eq!(NetworkInterfaceMonitor::status_from_interface(Some(&up)), "active");
        assert_eq!(NetworkInterfaceMonitor::status_from_interface(Some(&down)), "inactive");
        assert_eq!(NetworkInterfaceMonitor::status_from_interface(Some(&unknown)), "unknown");
    }

    #[test]
    fn test_monitor_state_update_logic() {
        let monitor = NetworkInterfaceMonitor {
            interfaces: std::sync::Arc::new(dashmap::DashMap::new()),
        };
        
        let interface = SystemInterface {
            index: SystemInterfaceId::from(10),
            name: "test0".to_string(),
            oper_state: OperState::Up,
            addresses: vec![],
            vlan_id: None,
        };
        
        // Test upsert_link directly to avoid complex Netlink message construction in unit tests
        monitor.upsert_link(interface.clone());
        
        let retrieved = monitor.get("test0").expect("interface should exist");
        assert_eq!(retrieved.index, SystemInterfaceId::from(10));
        assert_eq!(retrieved.oper_state, OperState::Up);
        
        // Test remove_link logic
        let mut del_link = netlink_packet_route::link::LinkMessage::default();
        del_link.header.index = 10;
        monitor.remove_link(&del_link);
        
        assert!(monitor.get("test0").is_none());
    }
}
