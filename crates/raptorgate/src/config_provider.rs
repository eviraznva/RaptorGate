use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tokio::sync::Mutex;
use tonic::async_trait;

use crate::config::AppConfig;
use crate::disk_store::SingleDiskStore;

#[async_trait]
pub trait ConfigObserver: Send + Sync {
    async fn on_config_change(&self, new_config: &AppConfig) -> Result<()>;
}

pub struct AppConfigProvider {
    config: ArcSwap<AppConfig>,
    store: SingleDiskStore<AppConfig>,
    observers: Mutex<Vec<Arc<dyn ConfigObserver>>>,
}

impl AppConfigProvider {
    pub async fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();

        let dev_mode_raw = std::env::var("DEV_MODE").unwrap_or_else(|_| "false".into());
        let dev_mode = dev_mode_raw.to_lowercase() == "true";
        let dev_policy = match std::env::var("DEV_OVERRIDE_POLICY") {
            Ok(p) => Some(p),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                eprintln!("WARNING: Failed to read DEV_OVERRIDE_POLICY: {e}");
                None
            }
        };

        if dev_mode && dev_policy.is_none() {
            eprintln!("WARNING: DEV_MODE is enabled but DEV_OVERRIDE_POLICY is not set. Using default policy.");
        }

        let dev_config = dev_mode.then_some(crate::config::DevConfig {
            policy_override: dev_policy,
        });

        let capture_interfaces = std::env::var("CAPTURE_INTERFACES")
            .unwrap_or_else(|_| "eth1,eth2".into())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let pcap_timeout_ms: i32 = std::env::var("PCAP_TIMEOUT_MS")
            .unwrap_or_else(|_| "5000".into())
            .parse()
            .context("PCAP_TIMEOUT_MS must be an integer")?;

        let tun_device_name = std::env::var("TUN_DEVICE_NAME").unwrap_or_else(|_| "tun0".into());

        let tun_address = std::env::var("TUN_ADDRESS")
            .unwrap_or_else(|_| "10.254.254.1".into())
            .parse()
            .context("TUN_ADDRESS must be a valid IPv4 address")?;

        let tun_netmask = std::env::var("TUN_NETMASK")
            .unwrap_or_else(|_| "255.255.255.0".into())
            .parse()
            .context("TUN_NETMASK must be a valid IPv4 address")?;

        let grpc_socket_path = std::env::var("GRPC_SOCKET_PATH")
            .unwrap_or_else(|_| "./sockets/firewall.sock".into());

        let query_socket_path = std::env::var("QUERY_SOCKET_PATH")
            .unwrap_or_else(|_| "./sockets/query.sock".into());

        let pki_dir = std::env::var("RAPTORGATE_PKI_DIR")
            .unwrap_or_else(|_| "/var/lib/raptorgate/pki".into());

        let data_dir = std::env::var("POLICIES_DIRECTORY")
            .unwrap_or_else(|_| "./".into()).into();

        let config = AppConfig {
            capture_interfaces,
            pcap_timeout_ms,
            tun_device_name,
            tun_address,
            tun_netmask,
            data_dir,
            grpc_socket_path,
            query_socket_path,
            dev_config,
            pki_dir,
        };

        let store = SingleDiskStore::new("app_config", config.data_dir.clone());

        if store.save(config.clone()).await.is_err() {
            tracing::warn!("Failed to persist initial AppConfig to disk, continuing in-memory");
        }

        Ok(Self {
            config: ArcSwap::new(Arc::new(config)),
            store,
            observers: Mutex::new(Vec::new()),
        })
    }

    pub async fn register<T: ConfigObserver + 'static>(&self, observer: Arc<T>) {
        self.observers.lock().await.push(observer);
    }

    #[allow(clippy::assigning_clones)]
    pub async fn swap_config(&self, new_config: AppConfig) -> Result<()> {
        let old = self.config.load();
        let mut new = new_config;

        new.dev_config = old.dev_config.clone();

        self.store.save(new.clone()).await
            .context("failed to persist new AppConfig to disk")?;

        let loaded = self.store.load().await
            .context("failed to verify AppConfig round-trip after save");

        match loaded {
            Ok(_) => {
                let observers = self.observers.lock().await;
                for observer in observers.iter() {
                    observer.on_config_change(&new).await
                        .context("observer rejected config change")?;
                }

                drop(observers);
                self.config.swap(Arc::new(new));
                tracing::info!("AppConfig swapped successfully");
                Ok(())
            }
            Err(err) => {
                tracing::error!(error = %err, "AppConfig round-trip verification failed, rolling back");
                self.store.save((**old).clone()).await
                    .context("CRITICAL: failed to rollback AppConfig after verification failure")?;
                Err(err)
            }
        }
    }

    pub fn get_config(&self) -> arc_swap::Guard<Arc<AppConfig>> {
        self.config.load()
    }
}
