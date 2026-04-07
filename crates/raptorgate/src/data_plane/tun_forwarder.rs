use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use std::sync::Arc;
use tun::{AbstractDevice, AsyncDevice};

use crate::config::AppConfig;
use crate::config_provider::ConfigObserver;
use crate::data_plane::packet_context::PacketContext;
use crate::events::{Event, EventKind};

const ETH_HDR: usize = 14;

pub struct TunForwarder {
    device: ArcSwap<AsyncDevice>,
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
            device: ArcSwap::new(Arc::new(device)),
            config: ArcSwap::new(Arc::new(config.clone())),
        })
    }

    pub async fn forward(&self, ctx: &PacketContext) {
        let raw = ctx.borrow_raw();
        if raw.len() <= ETH_HDR {
            tracing::warn!(
                iface = %ctx.borrow_src_interface(),
                "packet too short to strip ethernet header, dropping"
            );
            return;
        }

        let device = self.device.load();
        if let Err(e) = device.send(&raw[ETH_HDR..]).await {
            tracing::error!(
                iface = %ctx.borrow_src_interface(),
                error = %e,
                "failed to forward packet to TUN"
            );
        }
    }
}

// TODO: test this once we actually set up a proper test env in vagrant
#[tonic::async_trait]
impl ConfigObserver for TunForwarder {
    async fn on_config_change(&self, new_config: &AppConfig) -> Result<()> {
        let old_config = self.config.load();
        let new_device = Self::create_device(new_config)
            .context("failed to create new TUN device")?;

        let old_device_name = old_config.tun_device_name.clone();
        let old_address = old_config.tun_address.to_string();
        let new_address = new_config.tun_address.to_string();


        self.device.store(Arc::new(new_device));
        self.config.store(Arc::new(new_config.clone()));

        let new_device = self.device.load();
        let new_device_name = new_device.as_ref().tun_name().unwrap_or("Device name fetch failed".to_owned());

        crate::events::emit(Event::new(EventKind::TunDeviceSwapped {
            old_device: old_device_name,
            new_device: new_device_name,
            old_address,
            new_address,
        }));

        tracing::info!(
            tun_device = %new_config.tun_device_name,
            tun_address = %new_config.tun_address,
            tun_netmask = %new_config.tun_netmask,
            "TunForwarder: device rebuilt and swapped"
        );
        Ok(())
    }
}
