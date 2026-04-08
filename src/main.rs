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
use crate::data_plane::nat::NatEngine;
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::data_plane::tun_forwarder::TunForwarder;
use crate::ip_defrag::{DefragConfig, IpDefragEngine};
use crate::pipeline::{Chain, Stage, StageOutcome};
use crate::dpi::DpiClassifier;
use crate::pipeline::wrappers::{DnsInspectionStage, DpiStage, FtpAlgStage, NatPostroutingStage, NatPreroutingStage, PolicyEvalStage, TcpClassificationStage, TlsInspectionStage, ValidationStage};
use crate::policy::nat::nat_rule::{NatAction, NatProtocol, NatRule};
use crate::policy::nat::nat_rules::NatRules;
use crate::policy::provider::DiskPolicyProvider;
use crate::query_server::{QueryHandler, QueryServer};
use crate::tls::{CaManager, MitmProxy, MitmProxyConfig, NoopIpsInspector, ServerKeyStore, TlsDecisionEngine};
use tokio_util::sync::CancellationToken;

static DNS_BLOCKLIST_TEMP: &str = include_str!("dnsBlockedList.txt");

#[tokio::main]
async fn main() {
    type DataPipeline =
        Chain<ValidationStage,
        Chain<DpiStage,
        Chain<TlsInspectionStage,
        Chain<DnsInspectionStage,
        Chain<NatPreroutingStage,
        Chain<TcpClassificationStage,
        Chain<PolicyEvalStage,
        Chain<NatPostroutingStage, FtpAlgStage>>>>>>>>;

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

    let (ca_info, tls_cert_forger, tls_untrust_forger, tls_client_config) = match CaManager::init(&config.pki_dir) {
        Ok(ca) => {
            tracing::info!(fingerprint = %ca.ca_info().fingerprint, "CA initialized");
            let info = ca.ca_info();

            let forger = Arc::new(
                ca.cert_forger(1024).expect("Failed to create cert forger"),
            );
            let untrust = Arc::new(
                ca.untrust_cert_forger(256).expect("Failed to create untrust cert forger"),
            );
            tracing::info!("Cert forgers ready (trust: 1024, untrust: 256)");

            let client_cfg = tls::rustls_config::build_client_config()
                .expect("Failed to build TLS client config");
            tracing::info!("TLS client config ready");

            (Some(info), Some(forger), Some(untrust), Some(client_cfg))
        }
        Err(err) => {
            eprintln!("Warning: CA initialization failed: {err}");
            (None, None, None, None)
        }
    };

    let server_key_store = Arc::new(ServerKeyStore::new(&config.pki_dir));
    let decision_engine = Arc::new(TlsDecisionEngine::new(
        &config.ssl_bypass_domains,
        Arc::clone(&server_key_store),
    ));

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

    if config.ssl_inspection_enabled {
        match (&tls_cert_forger, &tls_untrust_forger, &tls_client_config) {
            (Some(forger), Some(untrust), Some(client_cfg)) => {
                let listen_addr = config.mitm_listen_addr.parse()
                    .expect("MITM_LISTEN_ADDR must be a valid socket address");

                let proxy_config = MitmProxyConfig {
                    listen_addr,
                    client_config: Arc::clone(client_cfg),
                    cert_forger: Arc::clone(forger),
                    untrust_forger: Arc::clone(untrust),
                    decision_engine: Arc::clone(&decision_engine),
                    ips_inspector: Arc::new(NoopIpsInspector),
                    cancel: CancellationToken::new(),
                };

                match MitmProxy::bind(proxy_config).await {
                    Ok(proxy) => {
                        tokio::spawn(proxy.serve());
                        tracing::info!("SSL/TLS inspection enabled");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to start MITM proxy");
                    }
                }
            }
            _ => {
                tracing::error!("SSL inspection enabled but CA/TLS config not available");
            }
        }
    }

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
                head: TlsInspectionStage { enabled: config.ssl_inspection_enabled, decision_engine: Arc::clone(&decision_engine) },
                tail: Chain {
                    head: DnsInspectionStage { inspection: dns_inspection },
                    tail: Chain {
                        head: NatPreroutingStage { engine: Arc::clone(&nat_engine) },
                        tail: Chain {
                            head: TcpClassificationStage { tracker: Arc::clone(&tcp_session_tracker) },
                            tail: Chain {
                                head: PolicyEvalStage { provider: Arc::clone(&policy_provider) },
                                tail: Chain {
                                    head: NatPostroutingStage { engine: Arc::clone(&nat_engine) },
                                    tail: FtpAlgStage { engine: Arc::clone(&nat_engine) },
                                },
                            },
                        },
                    },
                },
            },
        },
    };

    while let Some(raw_packet) = raw_rx.recv().await {
        if let Some(mut ctx) = defrag.process_raw(raw_packet) {
            let pipeline = pipeline.clone();
            tokio::spawn(async move {
                if !matches!(
                    &ctx.borrow_sliced_packet().net,
                    Some(NetSlice::Ipv4(_) | NetSlice::Ipv6(_))
                ) {
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
        (
            "eth1".to_string(),
            vec![
                "192.168.10.254".parse::<IpAddr>().unwrap(),
                "fd10::fe".parse::<IpAddr>().unwrap(),
            ],
        ),
        (
            "eth2".to_string(),
            vec![
                "192.168.20.254".parse::<IpAddr>().unwrap(),
                "fd20::fe".parse::<IpAddr>().unwrap(),
            ],
        ),
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
