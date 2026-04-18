use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::Mutex;
use tonic::async_trait;
use anyhow::{Context, Result};

use crate::config::AppConfig;
use crate::disk_store::SingleDiskStore;

#[async_trait]
pub trait ConfigObserver: Send + Sync {
    async fn on_config_change(&self, new_config: &AppConfig) -> Result<()>;
}

pub struct ConfigSwapError {
    pub original_error: anyhow::Error,
    pub rollback_failures: Vec<(&'static str, anyhow::Error)>,
}

impl fmt::Display for ConfigSwapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "config swap failed: {}", self.original_error)?;
        if !self.rollback_failures.is_empty() {
            writeln!(f, "rollback failures:")?;
            for (name, err) in &self.rollback_failures {
                writeln!(f, "  - {name}: {err}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ConfigSwapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for ConfigSwapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original_error.as_ref())
    }
}

pub struct AppConfigProvider {
    config: ArcSwap<AppConfig>,
    store: SingleDiskStore<AppConfig>,
    observers: Mutex<Vec<(Arc<dyn ConfigObserver>, &'static str)>>,
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

        let ssl_inspection_enabled = std::env::var("SSL_INSPECTION_ENABLED")
            .unwrap_or_else(|_| "false".into())
            .eq_ignore_ascii_case("true");

        let mitm_listen_addr = std::env::var("MITM_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8443".into());

        let control_plane_socket_path = std::env::var("CONTROL_PLANE_GRPC_SOCKET_PATH")
            .unwrap_or_else(|_| "./sockets/control-plane.sock".into());

        let server_cert_socket_path = std::env::var("SERVER_CERT_GRPC_SOCKET_PATH")
            .unwrap_or_else(|_| "./sockets/server-cert.sock".into());

        let ssl_bypass_domains: Vec<String> = std::env::var("SSL_BYPASS_DOMAINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let tls_inspection_ports = parse_tls_inspection_ports(
            std::env::var("TLS_INSPECTION_PORTS").ok().as_deref(),
        );

        let block_tls_on_undeclared_ports = std::env::var("BLOCK_TLS_ON_UNDECLARED_PORTS")
            .unwrap_or_else(|_| "false".into())
            .eq_ignore_ascii_case("true");

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
            ssl_inspection_enabled,
            mitm_listen_addr,
            control_plane_socket_path,
            server_cert_socket_path,
            ssl_bypass_domains,
            tls_inspection_ports,
            block_tls_on_undeclared_ports,
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

    pub async fn register<T: ConfigObserver + 'static>(&self, observer: Arc<T>, name: &'static str) {
        self.observers.lock().await.push((observer, name));
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
                let mut applied: Vec<usize> = Vec::new();

                for (i, (observer, name)) in observers.iter().enumerate() {
                    if let Err(e) = observer.on_config_change(&new).await {
                        let original_error = e.context(format!("{name} rejected config change"));
                        let mut rollback_failures = Vec::new();

                        for idx in applied.iter().rev() {
                            let (obs, obs_name) = &observers[*idx];
                            if let Err(rollback_err) = obs.on_config_change(&old).await {
                                rollback_failures.push((*obs_name, rollback_err));
                            }
                        }

                        if let Err(disk_err) = self.store.save((**old).clone()).await {
                            tracing::error!(error = %disk_err, "CRITICAL: failed to rollback AppConfig to disk after observer failure");
                        }

                        drop(observers);

                        if rollback_failures.is_empty() {
                            return Err(original_error);
                        }

                        return Err(anyhow::Error::new(ConfigSwapError {
                            original_error,
                            rollback_failures,
                        }));
                    }
                    applied.push(i);
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

fn parse_tls_inspection_ports(raw: Option<&str>) -> Vec<u16> {
    let parsed: Vec<u16> = raw
        .unwrap_or("443")
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect();

    if parsed.is_empty() {
        vec![443]
    } else {
        parsed
    }
}

#[cfg(test)]
mod tests {
    use super::parse_tls_inspection_ports;

    #[test]
    fn parse_tls_inspection_ports_defaults_to_443_when_absent() {
        assert_eq!(parse_tls_inspection_ports(None), vec![443]);
    }

    #[test]
    fn parse_tls_inspection_ports_reads_comma_separated_list() {
        assert_eq!(
            parse_tls_inspection_ports(Some("443, 8443 ,993")),
            vec![443, 8443, 993]
        );
    }

    #[test]
    fn parse_tls_inspection_ports_falls_back_on_empty_or_garbage() {
        assert_eq!(parse_tls_inspection_ports(Some("")), vec![443]);
        assert_eq!(parse_tls_inspection_ports(Some("abc,,")), vec![443]);
    }
}
