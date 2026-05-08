use anyhow::{Context, Result};
use arc_swap::{ArcSwap, ArcSwapOption};
use std::sync::Arc;
use tun::{AbstractDevice, AsyncDevice};

use crate::config::{AppConfig, ConfigObserver};
use crate::data_plane::packet_context::PacketContext;
use crate::events::{Event, EventKind};

const ETH_HDR: usize = 14;

pub struct TunForwarder {
    device: ArcSwapOption<AsyncDevice>,
    config: ArcSwap<AppConfig>,
}

impl TunForwarder {
    fn create_device(config: &AppConfig) -> Result<AsyncDevice> {
        let mut tun_config = tun::Configuration::default();
        tun_config
            .tun_name(&config.tun_device_name)
            .address(config.tun_address)
            .netmask(config.tun_netmask)
            .up();

        #[cfg(target_os = "linux")]
        tun_config.platform_config(|c| {
            c.ensure_root_privileges(true);
        });

        tun::create_as_async(&tun_config).context("failed to create TUN device")
    }

    /// # Panics
    /// Panics if the TUN device cannot be created with the provided configuration.
    #[must_use]
    pub fn new(config: &AppConfig) -> Arc<Self> {
        let device = Self::create_device(config).expect("failed to create TUN device");
        Arc::new(Self {
            device: ArcSwapOption::new(Some(Arc::new(device))),
            config: ArcSwap::new(Arc::new(config.clone())),
        })
    }

    pub async fn forward(&self, ctx: &PacketContext) {
        let raw = ctx.borrow_raw();
        if raw.len() <= ETH_HDR {
            tracing::warn!(
                event = "tun.forward.drop",
                iface = %ctx.borrow_src_interface(),
                packet_len = raw.len(),
                "packet too short to strip ethernet header, dropping"
            );
            return;
        }

        match &*self.device.load() {
            Some(dev) => {
                if let Err(e) = dev.send(&raw[ETH_HDR..]).await {
                    tracing::error!(
                        event = "tun.forward.failed",
                        iface = %ctx.borrow_src_interface(),
                        error = %e,
                        "failed to forward packet to TUN"
                    );
                }
            },
            None => tracing::warn!(
                event = "tun.forward.skipped",
                iface = %ctx.borrow_src_interface(),
                "TUN device not available"
            ),
        }
    }
}

#[tonic::async_trait]
impl ConfigObserver for TunForwarder {
    async fn on_config_change(&self, new_config: &AppConfig) -> Result<()> {
        let old_config = self.config.load();

        let old_device_name = old_config.tun_device_name.clone();
        let old_address = old_config.tun_address.to_string();
        let new_address = new_config.tun_address.to_string();

        self.device.store(None);

        let new_device = Self::create_device(new_config)?;

        self.device.store(Some(Arc::new(new_device)));
        self.config.store(Arc::new(new_config.clone()));

        let new_device = self.device.load();
        let new_device_name = new_device
            .as_ref().map_or_else(|| "Unknown".to_string(), |dev| dev.tun_name().unwrap_or_else(|_| "Unknown".to_string()));

        crate::events::emit(Event::new(EventKind::TunDeviceSwapped {
            old_device: old_device_name,
            new_device: new_device_name,
            old_address,
            new_address,
        }));

        tracing::info!(
            event = "tun.device.swapped",
            tun_device = %new_config.tun_device_name,
            tun_address = %new_config.tun_address,
            tun_netmask = %new_config.tun_netmask,
            "TunForwarder: device rebuilt and swapped"
        );
        Ok(())
    }
}
