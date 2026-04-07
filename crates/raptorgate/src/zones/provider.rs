use std::{collections::HashMap, sync::Arc};

use anyhow::Error;
use anyhow::Result;
use arc_swap::ArcSwap;
use uuid::Uuid;

use crate::{config::AppConfig, config_provider::ConfigObserver, disk_store::{ListDiskStore, SavedProperty}, zones::{DefaultPolicy, Zone, ZoneId, ZonePair, ZonePairId}};

pub struct ZonePairProvider {
    zone_pairs: ArcSwap<HashMap<ZonePairId, ZonePair>>,
    store: ListDiskStore<ZonePair>,
}

impl ZonePairProvider {
    pub async fn from_disk(config: &AppConfig) -> Self {
        let store: ListDiskStore<ZonePair> = ListDiskStore::new("zone_pairs", config.data_dir.clone());

        if let Ok(loaded) = store.load().await {
            #[allow(clippy::from_iter_instead_of_collect)]
            let zone_pairs: HashMap<ZonePairId, ZonePair> = HashMap::from_iter(
                loaded.into_iter().map(|prop| (prop.id.into(), prop.contents))
            );

            return Self { zone_pairs: Arc::new(zone_pairs).into(), store };
        }

        tracing::info!("no zone pairs found on disk, initializing with default zone pair");
        let default_zone_pair = ZonePair {
            src_zone_id: Uuid::now_v7().into(),
            dst_zone_id: Uuid::now_v7().into(),
            default_policy: DefaultPolicy::Unspecified,
        };

        let zone_pairs = ArcSwap::new(Arc::new(HashMap::from([(Uuid::now_v7().into(), default_zone_pair)])));

        Self { zone_pairs, store }
    }

    pub async fn swap_zone_pairs(&self, new_zone_pairs: Vec<(ZonePairId, ZonePair)>) -> Result<(), Error> {
        let old_zone_pairs = self.zone_pairs.load();

        self.store.save(new_zone_pairs.iter().cloned().map(|(id, zone)| SavedProperty {
            id: id.into(),
            contents: zone
        }).collect()).await?;

        let loaded = self.store.load().await;
        match loaded {
            Ok(loaded) => {
                let map = loaded.into_iter().map(|prop| (prop.id.into(), prop.contents)).collect();
                self.zone_pairs.swap(Arc::new(map));
            }

            Err(err) => {
                tracing::error!(error = %err, "failed to load zone_pairs after saving new zone_pairs");
                self.store.save(old_zone_pairs.iter().map(|(id, zone)| SavedProperty {
                    id: id.clone().into(), contents: zone.clone()
                }).collect()).await?; // if this fails we're in a really bad state
                return Err(err.into());
            }
        }

        #[allow(clippy::from_iter_instead_of_collect)]
        Ok(())
    }

    pub fn get_zone_pairs(&self) -> arc_swap::Guard<Arc<HashMap<ZonePairId, ZonePair>>> {
        self.zone_pairs.load()
    }

    pub fn get_zone_pair(&self, id: &ZonePairId) -> Option<ZonePair> {
        self.zone_pairs.load().get(id).cloned()
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
    zones: ArcSwap<HashMap<ZoneId, Zone>>,
    store: ListDiskStore<Zone>,
}

impl ZoneProvider {
    pub async fn from_disk(config: &AppConfig) -> Self {
        let store: ListDiskStore<Zone> = ListDiskStore::new("zones", config.data_dir.clone());
        if let Ok(loaded) = store.load().await {
            #[allow(clippy::from_iter_instead_of_collect)]
            let zones: HashMap<ZoneId, Zone> = HashMap::from_iter(
                loaded.into_iter().map(|prop| (prop.id.into(), prop.contents))
            );
            return Self { zones: Arc::new(zones).into(), store };
        }

        tracing::info!("no zones found on disk, initializing with default zone");
        let default_zone = Zone {
            name: "Default zone".into(),
            interface_ids: vec![],
        };

        let zones = ArcSwap::new(Arc::new(HashMap::from([(Uuid::now_v7().into(), default_zone)])));
        Self { zones, store }
    }

    pub async fn swap_zones(&self, new_zones: Vec<(ZoneId, Zone)>) -> Result<(), Error> {
        let old_zones = self.zones.load();

        self.store.save(new_zones.iter().cloned().map(|(id, zone)| SavedProperty {
            id: id.into(),
            contents: zone
        }).collect()).await?;

        let loaded = self.store.load().await;
        match loaded {
            Ok(loaded) => {
                let map = loaded.into_iter().map(|prop| (prop.id.into(), prop.contents)).collect();
                self.zones.swap(Arc::new(map));
            }

            Err(err) => {
                tracing::error!(error = %err, "failed to load zones after saving new zones");
                self.store.save(old_zones.iter().map(|(id, zone)| SavedProperty {
                    id: id.clone().into(), contents: zone.clone()
                }).collect()).await?; // if this fails we're in a really bad state
                return Err(err.into());
            }
        }

        #[allow(clippy::from_iter_instead_of_collect)]
        Ok(())
    }

    pub fn get_zones(&self) -> arc_swap::Guard<Arc<HashMap<ZoneId, Zone>>> {
        self.zones.load()
    }

    pub fn get_zone(&self, id: &ZoneId) -> Option<Zone> {
        self.zones.load().get(id).cloned()
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
