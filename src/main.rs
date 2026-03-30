mod config;
mod data_plane;
mod dpi;
mod events;
mod ip_defrag;
mod packet_validator;
mod pipeline;
mod policy;
mod proto;
mod query_server;
mod rule_tree;
mod tls;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use etherparse::NetSlice;
use tokio::sync::Mutex;
use ipnet::IpNet;
use tracing::trace;
use crate::config::AppConfig;
use crate::data_plane::dns_inspection::{DnsInspection, DomainBlockTree, TunnelingDetectorConfig};
use crate::data_plane::interface_sniffer::InterfaceSniffer;
use crate::data_plane::nat::engine::NatEngine;
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::data_plane::tun_forwarder::TunForwarder;
use crate::ip_defrag::{DefragConfig, IpDefragEngine};
use crate::pipeline::{Chain, Stage, StageOutcome};
use crate::dpi::DpiClassifier;
use crate::pipeline::wrappers::{DnsInspectionStage, DpiStage, NatPostroutingStage, NatPreroutingStage, PolicyEvalStage, TcpClassificationStage, ValidationStage};
use crate::policy::nat::nat_rule::{NatAction, NatProtocol, NatRule};
use crate::policy::nat::nat_rules::NatRules;
use crate::policy::provider::DiskPolicyProvider;
use crate::query_server::{QueryHandler, QueryServer};
use crate::tls::CaManager;
use tokio_util::sync::CancellationToken;

static DNS_BLOCKLIST_TEMP: &str = include_str!("dnsBlockedList.txt");

#[tokio::main]
async fn main() {
    type DataPipeline =
        Chain<ValidationStage,
        Chain<DpiStage,
        Chain<DnsInspectionStage,
        Chain<NatPreroutingStage,
        Chain<TcpClassificationStage,
        Chain<PolicyEvalStage, NatPostroutingStage>>>>>>;

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

    let tcp_session_tracker = TcpSessionTracker::new();
    let policy_provider = Arc::new(DiskPolicyProvider::new(&config));

    tokio::spawn(events::init_event_queue());
    let nat_engine = build_test_nat();

    let query_server = QueryServer::<DiskPolicyProvider>::new(
        QueryHandler {
            tcp_tracker: Arc::clone(&tcp_session_tracker),
            nat_engine: Arc::clone(&nat_engine),
            policy_store: Arc::clone(&policy_provider),
        },
        &config.query_socket_path,
        CancellationToken::new(),
    );
    tokio::spawn(query_server.serve());

    let defrag = IpDefragEngine::new(DefragConfig::default());

    let tun = TunForwarder::get(&config);

    let (_sniffer, mut raw_rx, errs) = InterfaceSniffer::with_sniffing(&config);
    for e in errs {
        tracing::error!(error = %e, "interface sniffer error");
    }

    let mut dns_block_tree = DomainBlockTree::new();

    dns_block_tree.load_from_array(DNS_BLOCKLIST_TEMP.lines());

    let dns_stats = dns_block_tree.stats();

    trace!("Loaded {} blocked domains into DNS inspection tree", dns_stats.total_nodes);
    dns_block_tree.print_tree();

    let dns_inspection = DnsInspection::new(dns_block_tree, TunnelingDetectorConfig::default());
    let dpi_classifier = Arc::new(DpiClassifier::new());
    
    let pipeline = DataPipeline {
        head: ValidationStage,
        tail: Chain {
            head: DpiStage { classifier: Arc::clone(&dpi_classifier) },
            tail: Chain {
                head: DnsInspectionStage { inspection: dns_inspection },
                tail: Chain {
                    head: NatPreroutingStage { engine: Arc::clone(&nat_engine) },
                    tail: Chain {
                        head: TcpClassificationStage { tracker: Arc::clone(&tcp_session_tracker) },
                        tail: Chain {
                            head: PolicyEvalStage { provider: policy_provider },
                            tail: NatPostroutingStage { engine: Arc::clone(&nat_engine) },
                        },
                    },
                },
            }
        },
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
