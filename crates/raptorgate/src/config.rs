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

    pub grpc_socket_path: String,
    pub query_socket_path: String,

    #[serde(skip)]
    pub dev_config: Option<DevConfig>,

    pub pki_dir: String,

    #[serde(default)]
    pub ssl_inspection_enabled: bool,
    #[serde(default = "default_mitm_listen_addr")]
    pub mitm_listen_addr: String,

    // Zmiana wymaga restartu — runtime swap nie rebinduje listenera.
    #[serde(default = "default_control_plane_socket_path")]
    pub control_plane_socket_path: String,

    // Seed startowy bypassow TLS. Zywy stan w TlsDecisionEngine, reload przez snapshot handler.
    #[serde(default)]
    pub ssl_bypass_domains: Vec<String>,

    #[serde(default = "default_tls_inspection_ports")]
    pub tls_inspection_ports: Vec<u16>,

    #[serde(default)]
    pub block_tls_on_undeclared_ports: bool,
}

fn default_mitm_listen_addr() -> String {
    "127.0.0.1:8443".to_string()
}

fn default_control_plane_socket_path() -> String {
    "./sockets/control-plane.sock".to_string()
}

fn default_tls_inspection_ports() -> Vec<u16> {
    vec![443]
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
            grpc_socket_path: self.grpc_socket_path.clone(),
            query_socket_path: self.query_socket_path.clone(),
            pki_dir: self.pki_dir.clone(),
            ssl_inspection_enabled: self.ssl_inspection_enabled,
            mitm_listen_addr: self.mitm_listen_addr.clone(),
            control_plane_socket_path: self.control_plane_socket_path.clone(),
            ssl_bypass_domains: self.ssl_bypass_domains.clone(),
            tls_inspection_ports: self
                .tls_inspection_ports
                .iter()
                .map(|port| u32::from(*port))
                .collect(),
            block_tls_on_undeclared_ports: self.block_tls_on_undeclared_ports,
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
            grpc_socket_path: proto_config.grpc_socket_path,
            query_socket_path: proto_config.query_socket_path,
            dev_config: None,
            pki_dir: proto_config.pki_dir,
            ssl_inspection_enabled: proto_config.ssl_inspection_enabled,
            mitm_listen_addr: if proto_config.mitm_listen_addr.is_empty() {
                default_mitm_listen_addr()
            } else {
                proto_config.mitm_listen_addr
            },
            control_plane_socket_path: if proto_config.control_plane_socket_path.is_empty() {
                default_control_plane_socket_path()
            } else {
                proto_config.control_plane_socket_path
            },
            ssl_bypass_domains: proto_config.ssl_bypass_domains,
            tls_inspection_ports: normalize_tls_inspection_ports(
                proto_config
                    .tls_inspection_ports
                    .into_iter()
                    .filter_map(|port| u16::try_from(port).ok())
                    .collect(),
            ),
            block_tls_on_undeclared_ports: proto_config.block_tls_on_undeclared_ports,
        })
    }
}

fn normalize_tls_inspection_ports(ports: Vec<u16>) -> Vec<u16> {
    if ports.is_empty() {
        default_tls_inspection_ports()
    } else {
        ports
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
            grpc_socket_path: "/tmp/firewall.sock".into(),
            query_socket_path: "/tmp/query.sock".into(),
            dev_config: None,
            pki_dir: "/tmp/pki".into(),
            ssl_inspection_enabled: false,
            mitm_listen_addr: default_mitm_listen_addr(),
            control_plane_socket_path: default_control_plane_socket_path(),
            ssl_bypass_domains: vec![],
            tls_inspection_ports: default_tls_inspection_ports(),
            block_tls_on_undeclared_ports: false,
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
          "grpc_socket_path": "./sockets/firewall.sock",
          "query_socket_path": "./sockets/query.sock",
          "pki_dir": "/var/lib/raptorgate/pki"
        }"#;

        let config: AppConfig = serde_json::from_str(raw).unwrap();
        assert_eq!(config.capture_interfaces, vec!["eth1"]);
        assert_eq!(config.tls_inspection_ports, vec![443]);
        assert!(!config.block_tls_on_undeclared_ports);
    }

    #[test]
    fn from_proto_normalizes_empty_tls_inspection_ports() {
        let mut config = sample_app_config();
        config.tls_inspection_ports = vec![];
        let roundtrip = AppConfig::from_proto(config.to_proto()).unwrap();
        assert_eq!(roundtrip.tls_inspection_ports, vec![443]);
    }

    #[test]
    fn from_proto_preserves_custom_tls_inspection_ports() {
        let mut config = sample_app_config();
        config.tls_inspection_ports = vec![443, 8443, 993];
        config.block_tls_on_undeclared_ports = true;
        let roundtrip = AppConfig::from_proto(config.to_proto()).unwrap();
        assert_eq!(roundtrip.tls_inspection_ports, vec![443, 8443, 993]);
        assert!(roundtrip.block_tls_on_undeclared_ports);
    }
}
