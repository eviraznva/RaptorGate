use std::sync::Arc;

use tun::AsyncDevice;

mod config;
mod control_plane;
mod data_plane;
mod frame;
mod ip_defrag;
mod policy;
mod policy_evaluator;
mod rule_tree;
mod tls;

use crate::config::AppConfig;
use crate::control_plane::{ControlPlane, ControlPlaneConfig};
use crate::data_plane::policy_store::PolicyStore;
use crate::data_plane::runtime as data_plane_runtime;
use crate::policy_evaluator::PolicyEvaluator;
use crate::rule_tree::{ArmEnd, FieldValue, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict};
use crate::tls::CaManager;

#[tokio::main]
async fn main() {
    let config = match AppConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {e}");
            return;
        }
    };

    let all_devices = match pcap::Device::list() {
        Ok(list) => list,
        Err(err) => {
            eprintln!("Device lookup error: {err:?}");
            return;
        }
    };

    let devices: Vec<pcap::Device> = all_devices
        .into_iter()
        .filter(|dev| config.capture_interfaces.contains(&dev.name))
        .collect();

    if devices.is_empty() {
        eprintln!("No matching devices found");
        return;
    }

    println!(
        "Using devices: {}",
        devices
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let tun = match setup_tun(&config.tun_device_name, config.tun_address, config.tun_netmask) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            eprintln!("Can't set up tun: {e:?}");
            return;
        }
    };

    let ca_info = match CaManager::init(&config.pki_dir) {
        Ok(ca) => {
            tracing::info!(fingerprint = %ca.ca_info().fingerprint, "CA initialized");
            Some(ca.ca_info())
        }
        Err(err) => {
            eprintln!("Warning: CA initialization failed: {err}");
            None
        }
    };

    let cp_config = ControlPlaneConfig {
        ca_info,
        ..ControlPlaneConfig::from(&config)
    };

    let control_plane = match ControlPlane::start(cp_config).await {
        Ok(control_plane) => control_plane,
        Err(err) => {
            eprintln!("Control plane startup error: {err:?}");
            return;
        }
    };
}

fn build_policy(block_icmp: bool) -> PolicyEvaluator {
    use frame::Protocol;

    let tree = if block_icmp {
        RuleTree::new(
            "default".into(),
            "Block ICMP, allow everything else".into(),
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Equal(FieldValue::Protocol(Protocol::Icmp)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .arm(Pattern::Wildcard, ArmEnd::Verdict(Verdict::Allow))
            .build()
            .expect("default policy is valid"),
        )
    } else {
        RuleTree::new(
            "default".into(),
            "Allow everything".into(),
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Wildcard,
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .expect("default policy is valid"),
        )
    };

    PolicyEvaluator::new(tree, Verdict::Drop)
}

fn setup_tun(name: &str, address: std::net::Ipv4Addr, netmask: std::net::Ipv4Addr) -> tun::Result<AsyncDevice> {
    let mut config = tun::Configuration::default();
    config
        .tun_name(name)
        .address(address)
        .netmask(netmask)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    tun::create_as_async(&config)
}
