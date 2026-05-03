use std::{collections::HashMap, sync::Arc};

use anyhow::Error;
use anyhow::Result;
use arc_swap::ArcSwap;
use uuid::Uuid;

use crate::{
    config::{AppConfig, ConfigObserver},
    disk_store::ListDiskStore,
    interfaces::{InterfaceMonitor, OperState},
    swapper::Swapper,
    zones::{
        DefaultPolicy, InterfaceStatus, Zone, ZoneId, ZoneInterface, ZoneInterfaceId, ZonePair,
        ZonePairId,
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
            let name_index = ArcSwap::new(Arc::new(build_name_index(items.iter())));
            return Self { swapper: Swapper::new(items, store), name_index };
        }

        tracing::info!("no zone interfaces found on disk, initializing empty");
        let name_index = ArcSwap::new(Arc::new(HashMap::new()));
        Self { swapper: Swapper::new(HashMap::new(), store), name_index }
    }

    pub async fn swap_zone_interfaces(&self, new: Vec<(ZoneInterfaceId, ZoneInterface)>) -> Result<(), Error> {
        let name_index = build_name_index(new.iter().map(|(id, zone_interface)| (id, zone_interface)));
        self.swapper.swap(new).await?;
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

    pub fn get_live_zone_interfaces<M>(&self, monitor: &M) -> HashMap<ZoneInterfaceId, ZoneInterface>
    where
        M: InterfaceMonitor,
    {
        self.swapper
            .get_all()
            .iter()
            .map(|(id, zone_interface)| {
                let mut enriched = zone_interface.clone();

                match monitor.get(zone_interface.interface_name()) {
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

fn build_name_index<'a, I>(entries: I) -> HashMap<String, ZoneInterfaceId>
where
    I: IntoIterator<Item = (&'a ZoneInterfaceId, &'a ZoneInterface)>,
{
    entries
        .into_iter()
        .map(|(id, zone_interface)| (zone_interface.interface_name().to_string(), id.clone()))
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
