use std::{collections::HashMap, sync::Arc};

use anyhow::Error;
use anyhow::Result;
use uuid::Uuid;

use crate::{config::{AppConfig, ConfigObserver}, disk_store::ListDiskStore, swapper::Swapper, zones::{DefaultPolicy, Zone, ZoneId, ZonePair, ZonePairId}};

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
