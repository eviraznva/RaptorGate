use std::sync::Arc;
use std::path::PathBuf;

use arc_swap::ArcSwap;
use anyhow::{Context, Result};

use crate::disk_store::SingleDiskStore;
use crate::data_plane::dns_inspection::config::DnsInspectionConfig;

/// Provider konfiguracji inspekcji DNS.
///
/// Zarządza trwałym przechowywaniem konfiguracji na dysku za pomocą
/// [`SingleDiskStore`] oraz atomową podmianą aktywnej konfiguracji w pamięci
/// przez [`ArcSwap`].
///
/// Wzorzec oparty na `AppConfigProvider` / `ZonePairProvider`.
pub struct DnsInspectionConfigProvider {
    /// Aktywna konfiguracja — odczyt lock-free przez ArcSwap.
    config: ArcSwap<DnsInspectionConfig>,
    /// Magazyn dyskowy — serializacja/deserializacja do JSON.
    store: SingleDiskStore<DnsInspectionConfig>,
}

impl DnsInspectionConfigProvider {
    /// Ładuje konfigurację z dysku lub inicjalizuje domyślną, jeśli plik nie istnieje.
    pub async fn from_disk(data_dir: PathBuf) -> Self {
        let store = SingleDiskStore::new("dns_inspection_config", data_dir);

        let config = match store.load().await {
            Ok(loaded) => {
                tracing::info!("dns inspection config loaded from disk");
                loaded
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to load dns inspection config from disk, using default"
                );
                DnsInspectionConfig::default()
            }
        };

        Self {
            config: ArcSwap::new(Arc::new(config)),
            store,
        }
    }

    /// Zapisuje nową konfigurację na dysk i atomowo podmienia aktywną wersję w pamięci.
    ///
    /// W przypadku błędu weryfikacji round-trip po zapisie przywraca poprzednią
    /// konfigurację na dysku i zwraca błąd.
    pub async fn swap_config(&self, new_config: DnsInspectionConfig) -> Result<()> {
        let old = self.config.load_full();

        self.store.save(new_config.clone()).await
            .context("failed to save new dns inspection config to disk")?;

        let verified = self.store.load().await
            .context("dns inspection config round-trip verification failed after save");

        match verified {
            Ok(_) => {
                self.config.store(Arc::new(new_config));
                tracing::info!("dns inspection config swapped successfully");
                Ok(())
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "dns inspection config verification failed, rolling back"
                );

                if let Err(rollback_err) = self.store.save((*old).clone()).await {
                    tracing::error!(
                        error = %rollback_err,
                        "CRITICAL: failed to roll back dns inspection config to disk"
                    );
                }

                Err(err)
            }
        }
    }

    /// Zwraca aktualną konfigurację (odczyt lock-free przez ArcSwap).
    pub fn get_config(&self) -> arc_swap::Guard<Arc<DnsInspectionConfig>> {
        self.config.load()
    }
}
