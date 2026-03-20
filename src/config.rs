use anyhow::{Context, Result};
use std::net::Ipv4Addr;

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

    // gRPC / backend
    pub grpc_socket_path: String,
    pub firewall_version: String,
    pub heartbeat_interval_secs: u64,

    // Redb snapshot
    pub redb_snapshot_path: String,

    // PKI — przechowywanie certyfikatu CA i zaszyfrowanego klucza prywatnego
    pub pki_dir: String,
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

            grpc_socket_path: std::env::var("GRPC_SOCKET_PATH")
                .unwrap_or_else(|_| "./sockets/firewall.sock".into()),

            firewall_version: std::env::var("FIREWALL_VERSION")
                .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").into()),

            heartbeat_interval_secs: std::env::var("HEARTBEAT_INTERVAL_SECS")
                .unwrap_or_else(|_| "10".into())
                .parse()
                .context("HEARTBEAT_INTERVAL_SECS must be an integer")?,

            redb_snapshot_path: std::env::var("REDB_SNAPSHOT_PATH")
                .unwrap_or_else(|_| "./.data/snapshot.redb".into()),

            pki_dir: std::env::var("RAPTORGATE_PKI_DIR")
                .unwrap_or_else(|_| "/var/lib/raptorgate/pki".into()),
        })
    }
}
