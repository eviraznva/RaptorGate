mod config;
mod control_plane;
mod data_plane;
mod ip_defrag;
mod packet_validator;
mod policy;
mod policy_evaluator;
mod rule_tree;
mod tls;
mod pipeline;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use etherparse::NetSlice;
use tokio::sync::Mutex;
use ipnet::IpNet;

use crate::config::AppConfig;
use crate::control_plane::{ControlPlane, ControlPlaneConfig};
use crate::data_plane::interface_sniffer::InterfaceSniffer;
use crate::data_plane::nat::engine::NatEngine;
use crate::data_plane::policy_store::PolicyStore;
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::data_plane::tun_forwarder::TunForwarder;
use crate::ip_defrag::{DefragConfig, IpDefragEngine};
use crate::pipeline::{Chain, Stage, StageOutcome};
use crate::pipeline::wrappers::{PolicyEvalStage, TcpClassificationStage};
use crate::policy::nat::nat_rule::{NatAction, NatProtocol, NatRule};
use crate::policy::nat::nat_rules::NatRules;
use crate::tls::CaManager;

#[tokio::main]
async fn main() {
    type DataPipeline = Chain<PolicyEvalStage, TcpClassificationStage>;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
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
            eprintln!("Failed to start control plane: {err}");
            return;
        }
    };

    let handle = control_plane.handle();
    let (policy_store, _policy_sync_task) = PolicyStore::from_watch(handle.policy());
    let tcp_session_tracker = TcpSessionTracker::new();

    let defrag = IpDefragEngine::new(DefragConfig::default());

    let tun = TunForwarder::get(&config);

    let (_sniffer, mut raw_rx, errs) = InterfaceSniffer::with_sniffing(&config);
    for e in errs {
        tracing::error!(error = %e, "interface sniffer error");
    }


    let pipeline = DataPipeline {
        head: PolicyEvalStage { policies: Arc::clone(&policy_store) },
        tail: TcpClassificationStage { tracker: Arc::clone(&tcp_session_tracker) },
    };

    while let Some(raw_packet) = raw_rx.recv().await {
        if let Some(mut ctx) = defrag.process_raw(raw_packet) {
            let pipeline = pipeline.clone();
            tokio::spawn(async move {
                if !matches!(&ctx.borrow_sliced_packet().net, Some(NetSlice::Ipv4(_))) { // we should support Ipv6 and ARP at some point
                    return;
                }
                let result: StageOutcome = pipeline.process(&mut ctx).await;

                if matches!(result, StageOutcome::Continue) {
                    tun.forward(&ctx).await;
                }
            });
        }
    }

    if let Err(err) = control_plane.shutdown().await {
        eprintln!("Control plane shutdown error: {err}");
    }
}

fn build_test_nat() -> Arc<Mutex<NatEngine>> {
    let interface_ips = HashMap::from([
        ("eth1".to_string(), "192.168.10.254".parse::<IpAddr>().unwrap()),
        ("eth2".to_string(), "192.168.20.254".parse::<IpAddr>().unwrap()),
    ]);

    let rules = NatRules::new(vec![
        NatRule::new(
            "dnat-portfwd-8080-to-h1-80".to_string(),
            20,
            Some("eth2".to_string()),
            None,
            None,
            None,
            None,
            Some("192.168.10.10/32".parse::<IpNet>().unwrap()),
            Some(NatProtocol::Tcp),
            Some(80),
            Some(8080),
            NatAction::Dnat,
        ),
    ]);

    Arc::new(Mutex::new(NatEngine::new(
        &Some(Arc::new(rules)),
        interface_ips,
    )))
}
