mod config;
mod config_provider;
mod data_plane;
mod disk_store;
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
mod zones;

use crate::config_provider::AppConfigProvider;
use crate::data_plane::dns_inspection::dns_inspection::DnsInspection;
use crate::data_plane::dns_inspection::dnssec::DnssecProvider;
use crate::data_plane::dns_inspection::provider::DnsInspectionConfigProvider;
use crate::data_plane::interface_sniffer::InterfaceSniffer;
use crate::data_plane::ips::ips::Ips;
use crate::data_plane::ips::provider::IpsConfigProvider;
use crate::data_plane::nat::NatEngine;
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::data_plane::tun_forwarder::TunForwarder;
use crate::dpi::DpiClassifier;
use crate::ip_defrag::{DefragConfig, IpDefragEngine};
use crate::pipeline::wrappers::{
    DnsBlockListStage, DnsTunnelingStage, DpiStage, FtpAlgStage, IpsStage, NatPostroutingStage,
    NatPreroutingStage, PolicyEvalStage, TcpClassificationStage, ValidationStage,
};
use crate::pipeline::{Chain, Stage, StageOutcome};
use crate::policy::nat::nat_rule::{NatAction, NatProtocol, NatRule};
use crate::policy::nat::nat_rules::NatRules;
use crate::policy::provider::DiskPolicyProvider;
use crate::query_server::{QueryHandler, QueryServer};
use crate::tls::CaManager;
use etherparse::NetSlice;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() {
    type DataPipeline = Chain<
        ValidationStage,
        Chain<
            DpiStage,
            Chain<
                DnsBlockListStage,
                Chain<
                    DnsTunnelingStage,
                    Chain<
                        IpsStage,
                        Chain<
                            NatPreroutingStage,
                            Chain<
                                TcpClassificationStage,
                                Chain<PolicyEvalStage, Chain<NatPostroutingStage, FtpAlgStage>>,
                            >,
                        >,
                    >,
                >,
            >,
        >,
    >;

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();

    let config_provider = match AppConfigProvider::from_env().await {
        Ok(provider) => Arc::new(provider),
        Err(err) => {
            tracing::error!("Configuration error: {err}");
            return;
        }
    };

    let config = config_provider.get_config();

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
    let policy_provider = Arc::new(
        DiskPolicyProvider::from_loaded(&config)
            .await
            .expect("Failed to initialize policy provider"),
    );
    let zones = Arc::new(crate::zones::provider::ZoneProvider::from_disk(&config).await);
    let zone_pairs = Arc::new(crate::zones::provider::ZonePairProvider::from_disk(&config).await);

    config_provider
        .register(Arc::clone(&policy_provider), "DiskPolicyProvider")
        .await;
    config_provider
        .register(Arc::clone(&zones), "ZoneProvider")
        .await;
    config_provider
        .register(Arc::clone(&zone_pairs), "ZonePairProvider")
        .await;

    tokio::spawn(events::init_event_queue());
    let nat_engine = build_test_nat();

    // Inicjalizacja providera konfiguracji DNS inspection.
    let dns_inspection_store =
        Arc::new(DnsInspectionConfigProvider::from_disk(config.data_dir.clone()).await);
    let dns_initial_config = dns_inspection_store.get_config().clone();

    let dns_inspection = match DnsInspection::new((*dns_initial_config).clone()) {
        Ok(inspection) => inspection,
        Err(err) => {
            tracing::error!(error = %err, "failed to initialize DNS inspection");
            return;
        }
    };

    let ips_store = Arc::new(IpsConfigProvider::from_disk(config.data_dir.clone()).await);
    let ips_initial_config = ips_store.get_config().clone();
    let ips = match Ips::new((*ips_initial_config).clone()) {
        Ok(inspection) => inspection,
        Err(err) => {
            tracing::error!(error = %err, "failed to initialize IPS");
            return;
        }
    };

    let dpi_classifier = Arc::new(DpiClassifier::new());

    let query_server = QueryServer::<DiskPolicyProvider>::new(
        QueryHandler {
            tcp_tracker: Arc::clone(&tcp_session_tracker),
            nat_engine: Arc::clone(&nat_engine),
            policy_store: Arc::clone(&policy_provider),
            zone_store: zones,
            zone_pair_store: zone_pairs,
            config_provider: Arc::clone(&config_provider),
            dns_inspection_store: Arc::clone(&dns_inspection_store),
            dns_inspection: Arc::clone(&dns_inspection),
            ips_store: Arc::clone(&ips_store),
            ips: Arc::clone(&ips),
        },
        &config.query_socket_path,
        CancellationToken::new(),
    );
    tokio::spawn(query_server.serve());

    let defrag = IpDefragEngine::new(DefragConfig::default());

    let tun = TunForwarder::new(&config);
    config_provider
        .register(Arc::clone(&tun), "TunForwarder")
        .await;

    let (sniffer, mut raw_rx, errs) = InterfaceSniffer::with_sniffing(&config);
    let sniffer = Arc::new(sniffer);
    config_provider
        .register(Arc::clone(&sniffer), "InterfaceSniffer")
        .await;
    for e in errs {
        tracing::error!(error = %e, "interface sniffer error");
    }

    // Rzutujemy DnsInspection na DnssecProvider i wstrzykujemy do PolicyEvalStage.
    let dnssec_provider: Arc<dyn DnssecProvider> =
        Arc::clone(&dns_inspection) as Arc<dyn DnssecProvider>;

    let pipeline = DataPipeline {
        head: ValidationStage,
        tail: Chain {
            head: DpiStage {
                classifier: Arc::clone(&dpi_classifier),
            },
            tail: Chain {
                head: DnsBlockListStage {
                    inspection: Arc::clone(&dns_inspection),
                },
                tail: Chain {
                    head: DnsTunnelingStage {
                        inspection: Arc::clone(&dns_inspection),
                    },
                    tail: Chain {
                        head: IpsStage {
                            inspection: Arc::clone(&ips),
                        },
                        tail: Chain {
                            head: NatPreroutingStage {
                                engine: Arc::clone(&nat_engine),
                            },
                            tail: Chain {
                                head: TcpClassificationStage {
                                    tracker: Arc::clone(&tcp_session_tracker),
                                },
                                tail: Chain {
                                    head: PolicyEvalStage {
                                        provider: Arc::clone(&policy_provider),
                                        dnssec: Some(dnssec_provider),
                                    },
                                    tail: Chain {
                                        head: NatPostroutingStage {
                                            engine: Arc::clone(&nat_engine),
                                        },
                                        tail: FtpAlgStage {
                                            engine: Arc::clone(&nat_engine),
                                        },
                                    },
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
            let tun = Arc::clone(&tun);
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

    let rules = NatRules::new(vec![NatRule::new(
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
    )]);

    Arc::new(Mutex::new(NatEngine::new(
        &Some(Arc::new(rules)),
        interface_ips,
    )))
}
