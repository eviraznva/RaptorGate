use std::{collections::HashMap, sync::Arc};

use anyhow::Error;
use anyhow::Result;
use arc_swap::ArcSwap;
use uuid::Uuid;

use crate::{
    config::{AppConfig, ConfigObserver},
    disk_store::{ListDiskStore, SavedProperty},
    interfaces::{InterfaceMonitor, OperState},
    swapper::Swapper,
    zones::{
        DefaultPolicy, InterfaceStatus, PhysicalInterface, Zone, ZoneId, ZoneInterface,
        ZoneInterfaceId, ZoneInterfaceKind, ZonePair, ZonePairId,
    },
};

pub struct ZonePairProvider {
    swapper: Swapper<ZonePairId, ZonePair>,
    pair_index: ArcSwap<HashMap<(ZoneId, ZoneId), ZonePairId>>,
}

impl ZonePairProvider {
    pub async fn from_disk(config: &AppConfig) -> Self {
        let store: ListDiskStore<ZonePair> = ListDiskStore::new("zone_pairs", config.data_dir.clone());

        if let Ok(loaded) = store.load().await {
            let mut zone_pairs: HashMap<ZonePairId, ZonePair> = HashMap::new();
            let mut pair_index = HashMap::new();
            for prop in loaded {
                let id: ZonePairId = prop.id.into();
                let pair = prop.contents;
                pair_index.insert((pair.src_zone_id.clone(), pair.dst_zone_id.clone()), id.clone());
                zone_pairs.insert(id, pair);
            }

            return Self { swapper: Swapper::new(zone_pairs, store), pair_index: ArcSwap::new(Arc::new(pair_index)) };
        }

        tracing::info!("no zone pairs found on disk, initializing with default zone pair");
        let default_zone_pair = ZonePair {
            src_zone_id: Uuid::nil().into(),
            dst_zone_id: Uuid::nil().into(),
            default_policy: DefaultPolicy::Unspecified,
        };

        let default_id: ZonePairId = Uuid::nil().into();
        let zone_pairs = HashMap::from([(default_id.clone(), default_zone_pair.clone())]);
        let mut pair_index = HashMap::new();
        pair_index.insert((default_zone_pair.src_zone_id.clone(), default_zone_pair.dst_zone_id.clone()), default_id);

        Self { swapper: Swapper::new(zone_pairs, store), pair_index: ArcSwap::new(Arc::new(pair_index)) }
    }

    pub async fn swap_zone_pairs(&self, new_zone_pairs: Vec<(ZonePairId, ZonePair)>) -> Result<(), Error> {
        let mut pair_index = HashMap::new();
        for (id, pair) in &new_zone_pairs {
            pair_index.insert((pair.src_zone_id.clone(), pair.dst_zone_id.clone()), id.clone());
        }
        self.swapper.swap(new_zone_pairs).await.map_err(anyhow::Error::from)?;
        self.pair_index.swap(Arc::new(pair_index));
        Ok(())
    }

    pub fn get_zone_pair_by_zones(&self, src: &ZoneId, dst: &ZoneId) -> Option<(ZonePairId, ZonePair)> {
        let index = self.pair_index.load();
        let id = index.get(&(src.clone(), dst.clone()))?;
        self.swapper.get(id).map(|pair| (id.clone(), pair))
    }

    pub fn get_zone_pairs(&self) -> arc_swap::Guard<Arc<HashMap<ZonePairId, ZonePair>>> {
        self.swapper.get_all()
    }

    pub fn get_zone_pair(&self, id: &ZonePairId) -> Option<ZonePair> {
        self.swapper.get(id)
    }
}

#[tonic::async_trait]
impl ConfigObserver for ZonePairProvider {
    async fn on_config_change(&self, new_config: &AppConfig) -> Result<()> {
        tracing::info!(
            data_dir = ?new_config.data_dir,
            "ZonePairProvider: config changed (stub — no reinitialization yet)"
        );
        Ok(())
    }
}

pub struct ZoneProvider {
    swapper: Swapper<ZoneId, Zone>,
}

impl ZoneProvider {
    pub async fn from_disk(config: &AppConfig) -> Self {
        let store: ListDiskStore<Zone> = ListDiskStore::new("zones", config.data_dir.clone());
        if let Ok(loaded) = store.load().await {
            #[allow(clippy::from_iter_instead_of_collect)]
            let zones: HashMap<ZoneId, Zone> = HashMap::from_iter(
                loaded.into_iter().map(|prop| (prop.id.into(), prop.contents))
            );
            return Self { swapper: Swapper::new(zones, store) };
        }

        tracing::info!("no zones found on disk, initializing with default zone");
        let default_zone = Zone {
            name: "Default zone".into(),
        };

        let zones = HashMap::from([(Uuid::nil().into(), default_zone)]);
        Self { swapper: Swapper::new(zones, store) }
    }

    pub async fn swap_zones(&self, new_zones: Vec<(ZoneId, Zone)>) -> Result<(), Error> {
        self.swapper.swap(new_zones).await.map_err(|e| e.into())
    }

    pub fn get_zones(&self) -> arc_swap::Guard<Arc<HashMap<ZoneId, Zone>>> {
        self.swapper.get_all()
    }

    pub fn get_zone(&self, id: &ZoneId) -> Option<Zone> {
        self.swapper.get(id)
    }
}

#[tonic::async_trait]
impl ConfigObserver for ZoneProvider {
    async fn on_config_change(&self, new_config: &AppConfig) -> Result<()> {
        tracing::info!(
            data_dir = ?new_config.data_dir,
            "ZoneProvider: config changed (stub — no reinitialization yet)"
        );
        Ok(())
    }
}

pub struct ZoneInterfaceProvider {
    swapper: Swapper<ZoneInterfaceId, ZoneInterface>,
    name_index: ArcSwap<HashMap<String, ZoneInterfaceId>>,
}

impl ZoneInterfaceProvider {
    pub async fn from_disk(config: &AppConfig) -> Self {
        let store: ListDiskStore<ZoneInterface> = ListDiskStore::new("zone_interfaces", config.data_dir.clone());
        if let Ok(loaded) = store.load().await {
            #[allow(clippy::from_iter_instead_of_collect)]
            let items: HashMap<ZoneInterfaceId, ZoneInterface> = HashMap::from_iter(
                loaded.into_iter().map(|prop| (prop.id.into(), prop.contents))
            );
            let name_index = ArcSwap::new(Arc::new(build_name_index(&items)));
            return Self { swapper: Swapper::new(items, store), name_index };
        }

        tracing::info!("no zone interfaces found on disk, initializing empty");
        let name_index = ArcSwap::new(Arc::new(HashMap::new()));
        Self { swapper: Swapper::new(HashMap::new(), store), name_index }
    }

    pub async fn collect<M: InterfaceMonitor>(config: &AppConfig, monitor: &M) -> Self {
        let store: ListDiskStore<ZoneInterface> =
            ListDiskStore::new("zone_interfaces", config.data_dir.clone());

        let mut loaded_items: HashMap<ZoneInterfaceId, ZoneInterface> =
            if let Ok(loaded) = store.load().await {
                #[allow(clippy::from_iter_instead_of_collect)]
                HashMap::from_iter(loaded.into_iter().map(|prop| (prop.id.into(), prop.contents)))
            } else {
                tracing::info!("no zone interfaces found on disk, initializing empty");
                HashMap::new()
            };

        let system_interfaces = monitor.snapshot();
        let mut changes_made = false;

        for (name, sys_iface) in system_interfaces {
            let exists = loaded_items
                .iter()
                .any(|(id, _)| crate::zones::resolve_os_name(&loaded_items, id).as_deref() == Some(name.as_str()));
            if !exists {
                let id = ZoneInterfaceId(Uuid::now_v7());
                let new_zone_interface = ZoneInterface {
                    zone_id: Uuid::nil().into(),
                    kind: ZoneInterfaceKind::Physical(PhysicalInterface {
                        interface_name: name.clone(),
                    }),
                    status: match sys_iface.oper_state {
                        OperState::Up => InterfaceStatus::Active,
                        OperState::Down => InterfaceStatus::Inactive,
                        OperState::Unknown => InterfaceStatus::Unknown,
                    },
                    addresses: sys_iface
                        .addresses
                        .into_iter()
                        .map(|a| a.to_string())
                        .collect(),
                    sniffed: false,
                };

                tracing::info!(
                    interface = %name,
                    "Discovered new system interface, adding to zone interfaces"
                );
                loaded_items.insert(id, new_zone_interface);
                changes_made = true;
            }
        }

        if changes_made {
            let items_to_save: Vec<SavedProperty<ZoneInterface>> = loaded_items
                .iter()
                .map(|(id, contents)| SavedProperty {
                    id: id.clone().into(),
                    contents: contents.clone(),
                })
                .collect();

            if let Err(e) = store.save(items_to_save).await {
                tracing::error!("Failed to save collected zone interfaces: {}", e);
            }
        }

        let name_index = ArcSwap::new(Arc::new(build_name_index(&loaded_items)));
        Self { swapper: Swapper::new(loaded_items, store), name_index }
    }

    pub async fn swap_zone_interfaces(&self, new: Vec<(ZoneInterfaceId, ZoneInterface)>) -> Result<(), Error> {
        self.swapper.swap(new).await?;
        let name_index = build_name_index(&self.swapper.get_all());
        self.name_index.swap(Arc::new(name_index));
        Ok(())
    }

    pub fn get_zone_interfaces(&self) -> arc_swap::Guard<Arc<HashMap<ZoneInterfaceId, ZoneInterface>>> {
        self.swapper.get_all()
    }

    pub fn get_zone_interface(&self, id: &ZoneInterfaceId) -> Option<ZoneInterface> {
        self.swapper.get(id)
    }

    pub fn get_zone_interface_by_name(
        &self,
        name: &str,
    ) -> Option<(ZoneInterfaceId, ZoneInterface)> {
        let index = self.name_index.load();
        let id = index.get(name)?;
        self.swapper.get(id).map(|interface| (id.clone(), interface))
    }

    pub fn resolve_os_name(&self, id: &ZoneInterfaceId) -> Option<String> {
        crate::zones::resolve_os_name(&self.swapper.get_all(), id)
    }

    pub fn get_live_zone_interfaces<M>(&self, monitor: &M) -> HashMap<ZoneInterfaceId, ZoneInterface>
    where
        M: InterfaceMonitor,
    {
        let all_interfaces = self.swapper.get_all();
        all_interfaces
            .iter()
            .map(|(id, zone_interface)| {
                let mut enriched = zone_interface.clone();

                if let Some(resolved_name) = crate::zones::resolve_os_name(&all_interfaces, id) {
                    match monitor.get(&resolved_name) {
                        Some(system_interface) => {
                            enriched.status = match system_interface.oper_state {
                                OperState::Up => InterfaceStatus::Active,
                                OperState::Down => InterfaceStatus::Inactive,
                                OperState::Unknown => InterfaceStatus::Unknown,
                            };
                            enriched.addresses = system_interface
                                .addresses
                                .into_iter()
                                .map(|address| address.to_string())
                                .collect();
                        }
                        None => {
                            enriched.status = InterfaceStatus::Missing;
                            enriched.addresses = Vec::new();
                        }
                    }
                } else {
                    enriched.status = InterfaceStatus::Missing;
                    enriched.addresses = Vec::new();
                }

                (id.clone(), enriched)
            })
            .collect()
    }

    #[cfg(test)]
    pub fn new_for_test(map: HashMap<ZoneInterfaceId, ZoneInterface>) -> Self {
        let name_index = build_name_index(&map);
        let store = ListDiskStore::new("test_zone_interfaces", std::path::PathBuf::from("/tmp"));
        Self {
            swapper: Swapper::new(map, store),
            name_index: ArcSwap::new(Arc::new(name_index)),
        }
    }
}

fn build_name_index(entries: &HashMap<ZoneInterfaceId, ZoneInterface>) -> HashMap<String, ZoneInterfaceId> {
    entries
        .iter()
        .filter_map(|(id, _zone_interface)| {
            crate::zones::resolve_os_name(entries, id).map(|name| (name, id.clone()))
        })
        .collect()
}

#[tonic::async_trait]
impl ConfigObserver for ZoneInterfaceProvider {
    async fn on_config_change(&self, new_config: &AppConfig) -> Result<()> {
        tracing::info!(
            data_dir = ?new_config.data_dir,
            "ZoneInterfaceProvider: config changed (stub — no reinitialization yet)"
        );
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::interfaces::{InterfaceMonitor, OperState, SystemInterface, SystemInterfaceId};
    use ipnet::IpNet;

    struct MockMonitor {
        interfaces: HashMap<String, SystemInterface>,
    }

    impl InterfaceMonitor for MockMonitor {
        fn get(&self, name: &str) -> Option<SystemInterface> {
            self.interfaces.get(name).cloned()
        }

        fn get_by_index(&self, _index: SystemInterfaceId) -> Option<SystemInterface> {
            None
        }

        fn snapshot(&self) -> HashMap<String, SystemInterface> {
            self.interfaces.clone()
        }
    }

    fn test_uuid() -> Uuid {
        Uuid::now_v7()
    }

    #[test]
    fn resolve_os_name_physical() {
        let mut interfaces = HashMap::new();
        let id = ZoneInterfaceId::from(test_uuid());
        let zi = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Physical(crate::zones::PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(id.clone(), zi);

        let name = crate::zones::resolve_os_name(&interfaces, &id);
        assert_eq!(name, Some("eth0".to_string()));
    }

    #[test]
    fn resolve_os_name_vlan() {
        let mut interfaces = HashMap::new();
        let parent_id = ZoneInterfaceId::from(test_uuid());
        let vlan_id = ZoneInterfaceId::from(test_uuid());

        let parent = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Physical(crate::zones::PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(parent_id.clone(), parent);

        let vlan = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Vlan(crate::zones::VlanSubinterface {
                parent_interface_id: parent_id,
                vlan_id: crate::zones::VlanId::try_from(100).unwrap(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(vlan_id.clone(), vlan);

        let name = crate::zones::resolve_os_name(&interfaces, &vlan_id);
        assert_eq!(name, Some("eth0.100".to_string()));
    }

    #[test]
    fn resolve_os_name_vlan_missing_parent() {
        let mut interfaces = HashMap::new();
        let vlan_id = ZoneInterfaceId::from(test_uuid());
        let missing_parent_id = ZoneInterfaceId::from(test_uuid());

        let vlan = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Vlan(crate::zones::VlanSubinterface {
                parent_interface_id: missing_parent_id,
                vlan_id: crate::zones::VlanId::try_from(100).unwrap(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(vlan_id.clone(), vlan);

        let name = crate::zones::resolve_os_name(&interfaces, &vlan_id);
        assert_eq!(name, None);
    }

    #[test]
    fn resolve_os_name_nonexistent_id() {
        let interfaces = HashMap::new();
        let id = ZoneInterfaceId::from(test_uuid());

        let name = crate::zones::resolve_os_name(&interfaces, &id);
        assert_eq!(name, None);
    }

    #[test]
    fn name_index_maps_physical_name() {
        let mut interfaces = HashMap::new();
        let id = ZoneInterfaceId::from(test_uuid());
        let zi = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Physical(crate::zones::PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(id.clone(), zi);

        let index = build_name_index(&interfaces);
        assert_eq!(index.get("eth0"), Some(&id));
    }

    #[test]
    fn name_index_maps_vlan_derived_name() {
        let mut interfaces = HashMap::new();
        let parent_id = ZoneInterfaceId::from(test_uuid());
        let vlan_id = ZoneInterfaceId::from(test_uuid());

        let parent = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Physical(crate::zones::PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(parent_id.clone(), parent);

        let vlan = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Vlan(crate::zones::VlanSubinterface {
                parent_interface_id: parent_id,
                vlan_id: crate::zones::VlanId::try_from(100).unwrap(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(vlan_id.clone(), vlan);

        let index = build_name_index(&interfaces);
        assert_eq!(index.get("eth0.100"), Some(&vlan_id));
    }

    #[test]
    fn name_index_does_not_find_vlan_by_parent_name() {
        let mut interfaces = HashMap::new();
        let parent_id = ZoneInterfaceId::from(test_uuid());
        let vlan_id = ZoneInterfaceId::from(test_uuid());

        let parent = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Physical(crate::zones::PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(parent_id.clone(), parent);

        let vlan = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Vlan(crate::zones::VlanSubinterface {
                parent_interface_id: parent_id.clone(),
                vlan_id: crate::zones::VlanId::try_from(100).unwrap(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(vlan_id, vlan);

        let index = build_name_index(&interfaces);
        assert_eq!(index.get("eth0"), Some(&parent_id));
    }

    #[test]
    fn get_live_zone_interfaces_physical() {
        let mut interfaces = HashMap::new();
        let id = ZoneInterfaceId::from(test_uuid());
        let zi = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Physical(crate::zones::PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Unspecified,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(id.clone(), zi);

        let mut monitor_data = HashMap::new();
        monitor_data.insert("eth0".to_string(), SystemInterface {
            index: SystemInterfaceId::from(1),
            name: "eth0".to_string(),
            oper_state: OperState::Up,
            addresses: vec!["192.168.1.1/24".parse::<IpNet>().unwrap()],
            vlan_id: None,
        });
        let monitor = MockMonitor { interfaces: monitor_data };

        let live = get_live_interfaces_helper(&interfaces, &monitor);
        let enriched = live.get(&id).unwrap();
        assert!(matches!(enriched.status, InterfaceStatus::Active));
        assert_eq!(enriched.addresses, vec!["192.168.1.1/24"]);
    }

    #[test]
    fn get_live_zone_interfaces_vlan_resolved() {
        let mut interfaces = HashMap::new();
        let parent_id = ZoneInterfaceId::from(test_uuid());
        let vlan_id = ZoneInterfaceId::from(test_uuid());

        let parent = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Physical(crate::zones::PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(parent_id.clone(), parent);

        let vlan = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Vlan(crate::zones::VlanSubinterface {
                parent_interface_id: parent_id,
                vlan_id: crate::zones::VlanId::try_from(100).unwrap(),
            }),
            status: InterfaceStatus::Unspecified,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(vlan_id.clone(), vlan);

        let mut monitor_data = HashMap::new();
        monitor_data.insert("eth0.100".to_string(), SystemInterface {
            index: SystemInterfaceId::from(2),
            name: "eth0.100".to_string(),
            oper_state: OperState::Up,
            addresses: vec!["10.0.0.1/24".parse::<IpNet>().unwrap()],
            vlan_id: Some(100),
        });
        let monitor = MockMonitor { interfaces: monitor_data };

        let live = get_live_interfaces_helper(&interfaces, &monitor);
        let enriched = live.get(&vlan_id).unwrap();
        assert!(matches!(enriched.status, InterfaceStatus::Active));
        assert_eq!(enriched.addresses, vec!["10.0.0.1/24"]);
    }

    #[test]
    fn get_live_zone_interfaces_vlan_missing_in_os() {
        let mut interfaces = HashMap::new();
        let parent_id = ZoneInterfaceId::from(test_uuid());
        let vlan_id = ZoneInterfaceId::from(test_uuid());

        let parent = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Physical(crate::zones::PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        interfaces.insert(parent_id.clone(), parent);

        let vlan = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Vlan(crate::zones::VlanSubinterface {
                parent_interface_id: parent_id,
                vlan_id: crate::zones::VlanId::try_from(100).unwrap(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec!["10.0.0.1".to_string()],
            sniffed: false,
        };
        interfaces.insert(vlan_id.clone(), vlan);

        let monitor = MockMonitor { interfaces: HashMap::new() };

        let live = get_live_interfaces_helper(&interfaces, &monitor);
        let enriched = live.get(&vlan_id).unwrap();
        assert!(matches!(enriched.status, InterfaceStatus::Missing));
        assert_eq!(enriched.addresses, Vec::<String>::new());
    }

    fn get_live_interfaces_helper<M: InterfaceMonitor>(
        interfaces: &HashMap<ZoneInterfaceId, ZoneInterface>,
        monitor: &M,
    ) -> HashMap<ZoneInterfaceId, ZoneInterface> {
        interfaces
            .iter()
            .map(|(id, zone_interface)| {
                let mut enriched = zone_interface.clone();

                if let Some(resolved_name) = crate::zones::resolve_os_name(interfaces, id) {
                    match monitor.get(&resolved_name) {
                        Some(system_interface) => {
                            enriched.status = match system_interface.oper_state {
                                OperState::Up => InterfaceStatus::Active,
                                OperState::Down => InterfaceStatus::Inactive,
                                OperState::Unknown => InterfaceStatus::Unknown,
                            };
                            enriched.addresses = system_interface
                                .addresses
                                .into_iter()
                                .map(|address| address.to_string())
                                .collect();
                        }
                        None => {
                            enriched.status = InterfaceStatus::Missing;
                            enriched.addresses = Vec::new();
                        }
                    }
                } else {
                    enriched.status = InterfaceStatus::Missing;
                    enriched.addresses = Vec::new();
                }

                (id.clone(), enriched)
            })
            .collect()
    }

    #[tokio::test]
    async fn swap_zone_interfaces_updates_name_index() {
        let temp_dir = std::env::temp_dir().join(format!("test_{}", test_uuid()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        
        let config = AppConfig {
            pcap_timeout_ms: 5000,
            tun_device_name: "tun0".into(),
            tun_address: "10.254.254.1".parse().unwrap(),
            tun_netmask: "255.255.255.0".parse().unwrap(),
            data_dir: temp_dir.clone(),
            event_socket_path: "/tmp/event.sock".into(),
            query_socket_path: "/tmp/query.sock".into(),
            dev_config: None,
            pki_dir: "/tmp/pki".into(),
            ssl_inspection_enabled: false,
            mitm_listen_addr: "127.0.0.1:8443".into(),
            control_plane_socket_path: "/tmp/control.sock".into(),
            server_cert_socket_path: "/tmp/server-cert.sock".into(),
            ssl_bypass_domains: Vec::new(),
            tls_inspection_ports: vec![443],
            block_tls_on_undeclared_ports: false,
        };

        let provider = ZoneInterfaceProvider::from_disk(&config).await;

        let parent_id = ZoneInterfaceId::from(test_uuid());
        let vlan_id = ZoneInterfaceId::from(test_uuid());

        let parent = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Physical(crate::zones::PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };

        let vlan = ZoneInterface {
            zone_id: ZoneId::from(test_uuid()),
            kind: crate::zones::ZoneInterfaceKind::Vlan(crate::zones::VlanSubinterface {
                parent_interface_id: parent_id.clone(),
                vlan_id: crate::zones::VlanId::try_from(100).unwrap(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };

        provider.swap_zone_interfaces(vec![
            (parent_id.clone(), parent),
            (vlan_id.clone(), vlan),
        ]).await.unwrap();

        assert_eq!(provider.get_zone_interface_by_name("eth0").map(|(id, _)| id), Some(parent_id));
        assert_eq!(provider.get_zone_interface_by_name("eth0.100").map(|(id, _)| id), Some(vlan_id));
        
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
