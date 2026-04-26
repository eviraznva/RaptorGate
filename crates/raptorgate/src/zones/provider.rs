use std::{collections::HashMap, sync::Arc};

use anyhow::Error;
use anyhow::Result;
use uuid::Uuid;

use crate::{
    config::{AppConfig, ConfigObserver},
    disk_store::{ListDiskStore, SavedProperty},
    interfaces::{InterfaceMonitor, OperState},
    swapper::Swapper,
    zones::{
        DefaultPolicy, InterfaceStatus, Zone, ZoneId, ZoneInterface, ZoneInterfaceId, ZonePair,
        ZonePairId,
    },
};

pub struct ZonePairProvider {
    swapper: Swapper<ZonePairId, ZonePair>,
}

impl ZonePairProvider {
    pub async fn from_disk(config: &AppConfig) -> Self {
        let store: ListDiskStore<ZonePair> = ListDiskStore::new("zone_pairs", config.data_dir.clone());

        if let Ok(loaded) = store.load().await {
            #[allow(clippy::from_iter_instead_of_collect)]
            let zone_pairs: HashMap<ZonePairId, ZonePair> = HashMap::from_iter(
                loaded.into_iter().map(|prop| (prop.id.into(), prop.contents))
            );

            return Self { swapper: Swapper::new(zone_pairs, store) };
        }

        tracing::info!("no zone pairs found on disk, initializing with default zone pair");
        let default_zone_pair = ZonePair {
            src_zone_id: Uuid::now_v7().into(),
            dst_zone_id: Uuid::now_v7().into(),
            default_policy: DefaultPolicy::Unspecified,
        };

        let zone_pairs = HashMap::from([(Uuid::now_v7().into(), default_zone_pair)]);

        Self { swapper: Swapper::new(zone_pairs, store) }
    }

    pub async fn swap_zone_pairs(&self, new_zone_pairs: Vec<(ZonePairId, ZonePair)>) -> Result<(), Error> {
        self.swapper.swap(new_zone_pairs).await.map_err(|e| e.into())
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
            interface_ids: vec![],
        };

        let zones = HashMap::from([(Uuid::now_v7().into(), default_zone)]);
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
}

impl ZoneInterfaceProvider {
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

        let tracked_names: Vec<String> = loaded_items.values().map(|zi| zi.interface_name.clone()).collect();
        for sys_iface in system_interfaces.values().filter(|val| !tracked_names.contains(&val.name)) {
            // let exists = loaded_items.values().any(|z| z.interface_name == name);
            let id = ZoneInterfaceId(Uuid::now_v7());
            let new_zone_interface = ZoneInterface {
                zone_id: Uuid::nil().into(),
                interface_name: sys_iface.name.clone(),
                vlan_id: sys_iface.vlan_id.map(Into::into),
                status: match sys_iface.oper_state {
                    OperState::Up => InterfaceStatus::Active,
                    OperState::Down => InterfaceStatus::Inactive,
                    OperState::Unknown => InterfaceStatus::Unknown,
                },
                addresses: sys_iface.clone()
                    .addresses
                    .into_iter()
                    .map(|a| a.to_string())
                    .collect(),
            };

            tracing::info!(
                interface = %sys_iface.name,
                "Discovered new system interface, adding to zone interfaces"
            );
            loaded_items.insert(id, new_zone_interface);
            changes_made = true;
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

        Self {
            swapper: Swapper::new(loaded_items, store),
        }
    }

    pub async fn swap_zone_interfaces(&self, new: Vec<(ZoneInterfaceId, ZoneInterface)>) -> Result<(), Error> {
        self.swapper.swap(new).await.map_err(|e| e.into())
    }

    pub fn get_zone_interfaces(&self) -> arc_swap::Guard<Arc<HashMap<ZoneInterfaceId, ZoneInterface>>> {
        self.swapper.get_all()
    }

    pub fn get_zone_interface(&self, id: &ZoneInterfaceId) -> Option<ZoneInterface> {
        self.swapper.get(id)
    }

    pub fn get_live_zone_interfaces<M>(&self, monitor: &M) -> HashMap<ZoneInterfaceId, ZoneInterface>
    where
        M: InterfaceMonitor,
    {
        self.swapper
            .get_all()
            .iter()
            .map(|(id, zone_interface)| {
                let mut enriched = zone_interface.clone();

                match monitor.get(&zone_interface.interface_name) {
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

                (id.clone(), enriched)
            })
            .collect()
    }
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
