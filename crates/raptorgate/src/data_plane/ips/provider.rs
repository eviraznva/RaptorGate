use std::sync::Arc;
use std::path::PathBuf;

use arc_swap::ArcSwap;
use anyhow::{Context, Result};

use crate::disk_store::SingleDiskStore;
use crate::data_plane::ips::config::IpsConfig;

pub struct IpsConfigProvider {
    config: ArcSwap<IpsConfig>,
    store: SingleDiskStore<IpsConfig>,
}

impl IpsConfigProvider {
    pub async fn from_disk(data_dir: PathBuf) -> Self {
        let store = SingleDiskStore::new("ips_config", data_dir);

        let config = match store.load().await {
            Ok(loaded) => {
                tracing::info!("ips config loaded from disk");
                loaded
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to load ips config from disk, using default");
                IpsConfig::default()
            }
        };

        Self {
            config: ArcSwap::new(Arc::new(config)),
            store,
        }
    }

    pub async fn swap_config(&self, new_config: IpsConfig) -> Result<()> {
        let old = self.config.load_full();

        self.store
            .save(new_config.clone())
            .await
            .context("failed to save new ips config to disk")?;

        let verified = self
            .store
            .load()
            .await
            .context("ips config round-trip verification failed after save");

        match verified {
            Ok(_) => {
                self.config.store(Arc::new(new_config));
                tracing::info!("ips config swapped successfully");
                Ok(())
            }
            Err(err) => {
                tracing::error!(error = %err, "ips config verification failed, rolling back");

                if let Err(rollback_err) = self.store.save((*old).clone()).await {
                    tracing::error!(
                        error = %rollback_err,
                        "CRITICAL: failed to roll back ips config to disk"
                    );
                }

                Err(err)
            }
        }
    }

    pub fn get_config(&self) -> arc_swap::Guard<Arc<IpsConfig>> {
        self.config.load()
    }
}
