mod config;
mod control_plane;
mod data_plane;
mod policy;
mod frame;
mod ip_defrag;
mod packet_validator;
mod policy_evaluator;
mod rule_tree;

use crate::config::AppConfig;
use crate::control_plane::{ControlPlane, ControlPlaneConfig};
use crate::data_plane::policy_store::PolicyStore;
use crate::data_plane::runtime as data_plane_runtime;

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

    let control_plane = match ControlPlane::start(ControlPlaneConfig::from(&config)).await {
        Ok(control_plane) => control_plane,
        Err(err) => {
            eprintln!("Failed to start control plane: {err}");
            return;
        }
    };

    let handle = control_plane.handle();
    let (policy_store, _policy_sync_task) = PolicyStore::from_watch(handle.policy());

    if let Err(err) = data_plane_runtime::run(&config, policy_store).await {
        eprintln!("Data plane error: {err}");
    }

    if let Err(err) = control_plane.shutdown().await {
        eprintln!("Control plane shutdown error: {err}");
    }
}
