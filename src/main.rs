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
use tracing_subscriber::fmt::format::FmtSpan;

#[tokio::main]
async fn main() {
    let verbose_log_format = control_plane::logging::env_flag("RAPTORGATE_LOG_VERBOSE_FORMAT");
    let log_level = std::env::var("RAPTORGATE_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_new(log_level.as_str())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(verbose_log_format)
        .with_thread_ids(verbose_log_format)
        .with_thread_names(verbose_log_format)
        .with_file(verbose_log_format)
        .with_line_number(verbose_log_format)
        .with_span_events(if verbose_log_format {
            FmtSpan::NEW | FmtSpan::CLOSE
        } else {
            FmtSpan::NONE
        })
        .init();

    tracing::info!(
        log_level = %log_level,
        verbose_log_format,
        "Initialized application logging"
    );

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
    )
    .await
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("Failed to start firewall IPC runtime: {err}");
            return;
        }
    };

    let state_rx = firewall_runtime.handle().state();

    tracing::info!("Starting data plane runtime");

    if let Err(err) = data_plane_runtime::run(&config, state_rx).await {
        eprintln!("Data plane error: {err}");
    }

    tracing::info!("Shutting down firewall IPC runtime");

    if let Err(err) = firewall_runtime.shutdown().await {
        eprintln!("Firewall IPC runtime shutdown error: {err}");
    }
}
