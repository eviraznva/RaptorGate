use std::sync::OnceLock;

use tun::AsyncDevice;

use crate::config::AppConfig;
use crate::data_plane::packet_context::PacketContext;

const ETH_HDR: usize = 14;

static FORWARDER: OnceLock<TunForwarder> = OnceLock::new();

pub struct TunForwarder {
    device: AsyncDevice,
}

impl TunForwarder {
    pub fn get(config: &AppConfig) -> &'static Self {
        FORWARDER.get_or_init(|| {
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

            let device = tun::create_as_async(&tun_config)
                .expect("failed to create TUN device");

            TunForwarder { device }
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

        if let Err(e) = self.device.send(&raw[ETH_HDR..]).await {
            tracing::error!(
                iface = %ctx.borrow_src_interface(),
                error = %e,
                "failed to forward packet to TUN"
            );
        }
    }
}
