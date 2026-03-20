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

    pub dev_config: Option<DevConfig>,
    // PKI — przechowywanie certyfikatu CA i zaszyfrowanego klucza prywatnego
    pub pki_dir: String,
}

pub struct DevConfig {
    pub policy_override: Option<String>,
}


impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();

        let dev_mode_raw = std::env::var("DEV_MODE").unwrap_or_else(|_| "false".into());
        let dev_mode = dev_mode_raw.to_lowercase() == "true";
        let dev_policy = match std::env::var("DEV_OVERRIDE_POLICY") {
            Ok(p) => Some(p),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                eprintln!("WARNING: Failed to read DEV_OVERRIDE_POLICY: {}", e);
                None
            }
        };

        if dev_mode && dev_policy.is_none() {
            eprintln!("WARNING: DEV_MODE is enabled but DEV_OVERRIDE_POLICY is not set. Using default policy.");
        }

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

            dev_config: dev_mode.then_some(DevConfig {
                policy_override: dev_policy,
            }),
            pki_dir: std::env::var("RAPTORGATE_PKI_DIR")
                .unwrap_or_else(|_| "/var/lib/raptorgate/pki".into()),
        }
        )}
}
