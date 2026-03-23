use std::sync::Arc;

use pcap::Direction;
use tokio::sync::{Mutex, mpsc};
use tokio::task;
use tun::AsyncDevice;

use crate::config::AppConfig;
use crate::data_plane::nat::engine::NatEngine;
use crate::data_plane::packet_handler::handle_packet;
use crate::data_plane::policy_store::PolicyStore;
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::ip_defrag::{DefragConfig, IpDefragEngine};

pub async fn run(
    config: &AppConfig,
    policies: Arc<PolicyStore>,
    nat: Arc<Mutex<NatEngine>>,
) -> anyhow::Result<()> {
    let all_devices = pcap::Device::list()?;

    let devices: Vec<pcap::Device> = all_devices
        .into_iter()
        .filter(|dev| config.capture_interfaces.contains(&dev.name))
        .collect();

    if devices.is_empty() {
        tracing::warn!(
            interfaces = %config.capture_interfaces.join(","),
            "No matching capture devices found — data plane inactive, control plane running"
        );
        std::future::pending::<()>().await;
        return Ok(());
    }

    println!(
        "Using devices: {}",
        devices
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let tun = Arc::new(setup_tun(
        &config.tun_device_name,
        config.tun_address,
        config.tun_netmask,
    )?);

    let defrag = Arc::new(IpDefragEngine::new(DefragConfig::default()));

    let pcap_timeout_ms = config.pcap_timeout_ms;
    let mut handles = Vec::new();

    for device in devices {
        let tun = Arc::clone(&tun);
        let policies = Arc::clone(&policies);
        let defrag = Arc::clone(&defrag);
        let nat = Arc::clone(&nat);
        let name = device.name.clone();
        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);

        let capture_name = name.clone();
        task::spawn_blocking(move || {
            let mut cap = match pcap::Capture::from_device(device)
                .map(|c| {
                    c.immediate_mode(true)
                        .promisc(true)
                        .timeout(pcap_timeout_ms)
                })
                .and_then(pcap::Capture::open)
            {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("[{capture_name}] Failed to open capture: {err:?}");
                    return;
                }
            };

            if let Err(err) = cap.direction(Direction::In) {
                eprintln!("[{capture_name}] Warning: could not set direction: {err:?}");
            }

            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        if tx.blocking_send(packet.data.to_vec()).is_err() {
                            eprintln!("[{capture_name}] Receiver dropped, stopping capture");
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
                    Err(err) => {
                        eprintln!("[{capture_name}] Capture error (fatal): {err:?}");
                        break;
                    }
                }
            }

            eprintln!("[{capture_name}] Capture thread exiting");
        });

        let handler_name = name;
        let tcp_sessions = Arc::clone(&tcp_sessions);
        let handle = tokio::spawn(async move {
            let mut rx = rx;
            while let Some(data) = rx.recv().await {
                handle_packet(&handler_name, &data, &tun, &policies, &defrag, &tcp_sessions).await;
            }
            eprintln!("[{handler_name}] Handler task exiting (sender dropped)");
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await?;
    }

    Ok(())
}

fn setup_tun(
    name: &str,
    address: std::net::Ipv4Addr,
    netmask: std::net::Ipv4Addr,
) -> tun::Result<AsyncDevice> {
    let mut config = tun::Configuration::default();
    config.tun_name(name).address(address).netmask(netmask).up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    tun::create_as_async(&config)
}
