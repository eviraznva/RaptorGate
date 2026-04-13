use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;

use crate::data_plane::nat::config::NatConfig;
use crate::disk_store::SingleDiskStore;

pub struct NatConfigProvider {
    config: ArcSwap<NatConfig>,
    store: SingleDiskStore<NatConfig>,
}

impl NatConfigProvider {
    pub async fn from_disk(data_dir: PathBuf) -> Self {
        let store = SingleDiskStore::new("nat_config", data_dir);

        let config = match store.load().await {
            Ok(loaded) => {
                tracing::info!("nat config loaded from disk");
                loaded
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to load nat config from disk, using empty config");
                NatConfig::default()
            }
        };

        Self {
            config: ArcSwap::new(Arc::new(config)),
            store,
        }
    }

    pub async fn swap_config(&self, new_config: NatConfig) -> Result<()> {
        let old = self.config.load_full();

        self.store
            .save(new_config.clone())
            .await
            .context("failed to save new nat config to disk")?;

        let verified = self
            .store
            .load()
            .await
            .context("nat config round-trip verification failed after save");

        match verified {
            Ok(_) => {
                self.config.store(Arc::new(new_config));
                tracing::info!("nat config swapped successfully");
                Ok(())
            }
            Err(err) => {
                tracing::error!(error = %err, "nat config verification failed, rolling back");

                if let Err(rollback_err) = self.store.save((*old).clone()).await {
                    tracing::error!(
                        error = %rollback_err,
                        "CRITICAL: failed to roll back nat config to disk"
                    );
                }

                Err(err)
            }
        }
    }

    pub fn get_config(&self) -> arc_swap::Guard<Arc<NatConfig>> {
        self.config.load()
    }
}
