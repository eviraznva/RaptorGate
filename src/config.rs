use std::net::Ipv4Addr;
use anyhow::{Context, Result};

pub struct AppConfig {
    // Packet capture
    pub capture_interfaces: Vec<String>,
    pub pcap_timeout_ms: i32,

    // TUN device
    pub tun_device_name: String,
    pub tun_address: Ipv4Addr,
    pub tun_netmask: Ipv4Addr,

    // Policy
    pub block_icmp: bool,
    pub dummy_nat_enabled: bool,
    pub dummy_nat_allow_all: bool,

    pub sync_ipc_socket_path: String,
    pub async_ipc_socket_path: String,
    pub heartbeat_interval_secs: u64,
    pub event_queue_capacity: usize,
    pub config_store_path: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();

        Ok(Self {
            capture_interfaces: std::env::var("CAPTURE_INTERFACES")
                .unwrap_or_else(|_| "enp0s8,enp0s9".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),

            pcap_timeout_ms: std::env::var("PCAP_TIMEOUT_MS")
                .unwrap_or_else(|_| "5000".into())
                .parse()
                .context("PCAP_TIMEOUT_MS must be an integer")?,

            tun_device_name: std::env::var("TUN_DEVICE_NAME").unwrap_or_else(|_| "tun0".into()),

            tun_address: std::env::var("TUN_ADDRESS")
                .unwrap_or_else(|_| "10.254.254.1".into())
                .parse()
                .context("TUN_ADDRESS must be a valid IPv4 address")?,

            tun_netmask: std::env::var("TUN_NETMASK")
                .unwrap_or_else(|_| "255.255.255.0".into())
                .parse()
                .context("TUN_NETMASK must be a valid IPv4 address")?,

            block_icmp: std::env::var("BLOCK_ICMP")
                .unwrap_or_else(|_| "false".into())
                .to_lowercase()
                == "true",

            dummy_nat_enabled: std::env::var("DUMMY_NAT_ENABLED")
                .unwrap_or_else(|_| "false".into())
                .to_lowercase()
                == "true",

            dummy_nat_allow_all: std::env::var("DUMMY_NAT_ALLOW_ALL")
                .unwrap_or_else(|_| "false".into())
                .to_lowercase()
                == "true",

            sync_ipc_socket_path: std::env::var("SYNC_IPC_SOCKET_PATH")
                .unwrap_or_else(|_| "./sockets/rg-synchronous.sock".into()),

            async_ipc_socket_path: std::env::var("ASYNC_IPC_SOCKET_PATH")
                .unwrap_or_else(|_| "./sockets/rg-asynchronous.sock".into()),

            heartbeat_interval_secs: std::env::var("HEARTBEAT_INTERVAL_SECS")
                .unwrap_or_else(|_| "10".into())
                .parse()
                .context("HEARTBEAT_INTERVAL_SECS must be an integer")?,

            event_queue_capacity: std::env::var("EVENT_QUEUE_CAPACITY")
                .unwrap_or_else(|_| "256".into())
                .parse()
                .context("EVENT_QUEUE_CAPACITY must be an integer")?,

            config_store_path: std::env::var("CONFIG_STORE_PATH")
                .unwrap_or_else(|_| "/etc/raptorgate/config/runtime".into()),
        })
    }
}
