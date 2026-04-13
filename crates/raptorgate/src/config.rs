use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, path::PathBuf};

use crate::proto::config as proto;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub capture_interfaces: Vec<String>,
    pub pcap_timeout_ms: i32,

    pub tun_device_name: String,
    pub tun_address: Ipv4Addr,
    pub tun_netmask: Ipv4Addr,

    pub data_dir: PathBuf,

    pub event_socket_path: String,
    pub query_socket_path: String,

    #[serde(skip)]
    pub dev_config: Option<DevConfig>,

    pub pki_dir: String,
}

#[derive(Clone, Debug)]
pub struct DevConfig {
    pub policy_override: Option<String>,
}

impl AppConfig {
    pub fn to_proto(&self) -> proto::AppConfig {
        proto::AppConfig {
            capture_interfaces: self.capture_interfaces.clone(),
            pcap_timeout_ms: self.pcap_timeout_ms,
            tun_device_name: self.tun_device_name.clone(),
            tun_address: self.tun_address.to_string(),
            tun_netmask: self.tun_netmask.to_string(),
            data_dir: self.data_dir.to_string_lossy().into_owned(),
            event_socket_path: self.event_socket_path.clone(),
            query_socket_path: self.query_socket_path.clone(),
            pki_dir: self.pki_dir.clone(),
        }
    }

    pub fn from_proto(proto_config: proto::AppConfig) -> Result<Self> {
        Ok(Self {
            capture_interfaces: proto_config.capture_interfaces,
            pcap_timeout_ms: proto_config.pcap_timeout_ms,
            tun_device_name: proto_config.tun_device_name,
            tun_address: proto_config
                .tun_address
                .parse()
                .context("tun_address must be a valid IPv4 address")?,
            tun_netmask: proto_config
                .tun_netmask
                .parse()
                .context("tun_netmask must be a valid IPv4 address")?,
            data_dir: proto_config.data_dir.into(),
            event_socket_path: proto_config.event_socket_path,
            query_socket_path: proto_config.query_socket_path,
            dev_config: None,
            pki_dir: proto_config.pki_dir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_app_config() -> AppConfig {
        AppConfig {
            capture_interfaces: vec!["eth0".into(), "eth1".into()],
            pcap_timeout_ms: 5000,
            tun_device_name: "tun0".into(),
            tun_address: "10.254.254.1".parse().unwrap(),
            tun_netmask: "255.255.255.0".parse().unwrap(),
            data_dir: "/tmp".into(),
            event_socket_path: "/tmp/firewall.sock".into(),
            query_socket_path: "/tmp/query.sock".into(),
            dev_config: None,
            pki_dir: "/tmp/pki".into(),
        }
    }

    #[test]
    fn app_config_proto_roundtrip() {
        let config = sample_app_config();
        let roundtrip = AppConfig::from_proto(config.to_proto()).unwrap();

        assert_eq!(roundtrip.capture_interfaces, vec!["eth0", "eth1"]);
        assert_eq!(roundtrip.tun_address.to_string(), "10.254.254.1");
        assert_eq!(roundtrip.pki_dir, "/tmp/pki");
    }

    #[test]
    fn app_config_json_deserializes() {
        let raw = r#"{
          "capture_interfaces": ["eth1"],
          "pcap_timeout_ms": 5000,
          "tun_device_name": "tun0",
          "tun_address": "10.254.254.1",
          "tun_netmask": "255.255.255.0",
          "data_dir": "./",
          "event_socket_path": "./sockets/firewall.sock",
          "query_socket_path": "./sockets/query.sock",
          "pki_dir": "/var/lib/raptorgate/pki"
        }"#;

        let config: AppConfig = serde_json::from_str(raw).unwrap();
        assert_eq!(config.capture_interfaces, vec!["eth1"]);
    }
}
