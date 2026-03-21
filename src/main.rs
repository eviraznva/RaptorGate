mod config;
mod control_plane;
mod data_plane;
mod frame;
mod ip_defrag;
mod packet_validator;
mod policy;
mod policy_evaluator;
mod rule_tree;
mod tls;

use crate::config::AppConfig;
use crate::data_plane::runtime as data_plane_runtime;
use control_plane::firewall_communication::{FirewallIpcConfig, FirewallIpcRuntime};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();

    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Configuration error: {err}");
            return;
        }
    };

    let firewall_runtime = match FirewallIpcRuntime::start(
        FirewallIpcConfig::from(&config),
        config.block_icmp,
    ).await {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("Failed to start firewall IPC runtime: {err}");
            return;
        }
    };

    let handle = firewall_runtime.handle();

    if let Err(err) = data_plane_runtime::run(&config, handle.state()).await {
        eprintln!("Data plane error: {err}");
    }

    if let Err(err) = firewall_runtime.shutdown().await {
        eprintln!("Firewall IPC runtime shutdown error: {err}");
    }
}
