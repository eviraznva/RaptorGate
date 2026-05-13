mod config;
mod conntrack;
mod control_server;
mod data_plane;
mod disk_store;
mod dpi;
mod events;
mod factory_reset;
mod identity;
mod interfaces;
mod ip_defrag;
mod logging;
mod metrics;
mod ml;
mod netlink;
mod packet_validator;
mod pipeline;
mod policy;
mod proto;
mod query_server;
mod routing;
mod rule_tree;
mod server_certificate_server;
mod tls;
mod zones;
mod swapper;
mod validation;
mod nat;

use crate::config::provider::AppConfigProvider;
use crate::control_server::ControlServer;
use crate::data_plane::dns_inspection::dns_inspection::DnsInspection;
use crate::data_plane::dns_inspection::dnssec::DnssecProvider;
use crate::data_plane::dns_inspection::provider::DnsInspectionConfigProvider;
use crate::data_plane::interface_sniffer::InterfaceSniffer;
use crate::data_plane::ips::ips::Ips;
use crate::data_plane::ips::provider::IpsConfigProvider;
use crate::nat::{NatConfigProvider, NatEngine};
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::data_plane::tun_forwarder::TunForwarder;
use crate::dpi::DpiClassifier;
use crate::identity::IdentitySessionStore;
use crate::ip_defrag::{DefragConfig, IpDefragEngine};
use crate::pipeline::wrappers::{
    ConntrackConfirmStage, ConntrackInStage, DnsBlockListStage, DnsEchMitigationStage,
    DnsTunnelingStage, DpiStage, FtpAlgStage, IdentityLookupStage, IpsStage, L4StateStage, LocalOwnershipStage,
    MetricsStage, MlAlertStage, NatPostroutingStage, NatPreroutingStage, PolicyEvalStage,
    TlsPortEnforcementStage, ValidationStage, SmtpStage,
};
use crate::pipeline::{Chain, ExecutionSink, ExecutionStage, Stage, StageOutcome};
use tokio::sync::mpsc;
use crate::policy::provider::DiskPolicyProvider;
use crate::query_server::{QueryHandler, QueryServer};
use crate::tls::{
    CaManager, DecryptedChainInspector, DecryptionMirror, DecryptionMirrorConfig, EchTlsPolicy, MitmProxy, MitmProxyConfig,
    PinningConfig, ServerKeyStore, TlsDecisionEngine, TransparentRedirect,
};
use crate::interfaces::{InterfaceMonitor, NetlinkInterfaceController, NetworkInterfaceMonitor};
use crate::netlink::listener::NetlinkListener;
use crate::netlink::routing_table::RoutingTable;
use etherparse::NetSlice;
use pcap::Device;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use crate::conntrack::config::ConntrackConfig;
use crate::conntrack::entry::{ConntrackEntry, CtStatus};
use crate::conntrack::observer::{AnomalyKind, CtObserver, DestroyReason, ObserverRegistry};
use crate::conntrack::proto::icmp::IcmpHandler;
use crate::conntrack::proto::ProtoRegistry;
use crate::conntrack::proto::tcp::TcpHandler;
use crate::conntrack::proto::udp::UdpHandler;
use crate::conntrack::reaper::Reaper;
use crate::conntrack::table::Conntrack;
use crate::conntrack::tuple::Direction as CtDirection;

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() {
    type DataPipeline<M> = Chain<
        ValidationStage,
        Chain<
            MetricsStage,
            Chain<
                LocalOwnershipStage,
                Chain<
                    IdentityLookupStage,
                    Chain<
                        ConntrackInStage,
                        Chain<
                            DpiStage,
                            Chain<
                                TlsPortEnforcementStage,
                                Chain<
                                    DnsBlockListStage,
                                    Chain<
                                        DnsTunnelingStage,
                                        Chain<
                                            DnsEchMitigationStage,
                                            Chain<
                                                IpsStage,
                                                Chain<
                                                    NatPreroutingStage,
                                                    Chain<
                                                        L4StateStage,
                                                        Chain<
                                                            MlAlertStage,
                                                            Chain<
                                                                PolicyEvalStage<zones::resolver::RoutingZoneResolver<M>>,
                                                                Chain<
                                                                    NatPostroutingStage<M>,
                                                                    Chain<
                                                                        FtpAlgStage,
                                                                        Chain<
                                                                            SmtpStage,
                                                                            Chain<ExecutionStage, ConntrackConfirmStage>,
                                                                        >,
                                                                    >,
                                                                >,
                                                            >,
                                                        >,
                                                    >,
                                                >,
                                            >,
                                        >,
                                    >,
                                >,
                            >,
                        >,
                    >,
                >,
            >,
        >,
    >;

    if let Err(err) = logging::init() {
        eprintln!("failed to initialize daily firewall logging: {err}");
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("RAPTORGATE_LOG_LEVEL")
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
            )
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .json()
            .flatten_event(true)
            .init();
    }

    tracing::info!(
        event = "startup.process.started",
        pid = std::process::id(),
        "raptorgate firewall process started"
    );

    let config_provider = match AppConfigProvider::from_env().await {
        Ok(provider) => Arc::new(provider),
        Err(err) => {
            tracing::error!(
                event = "startup.config.failed",
                error = %err,
                "configuration error"
            );
            return;
        }
    };

    let config = config_provider.get_config();
    tracing::info!(
        event = "startup.config.loaded",
        data_dir = %config.data_dir.display(),
        query_socket_path = %config.query_socket_path,
        event_socket_path = %config.event_socket_path,
        "firewall config loaded"
    );

    let (_ca_info, tls_cert_forger, tls_untrust_forger) = match CaManager::init(&config.pki_dir) {
        Ok(ca) => {
            tracing::info!(
                event = "startup.ca.initialized",
                fingerprint = %ca.ca_info().fingerprint,
                "CA initialized"
            );
            let info = ca.ca_info();
            let forger = Arc::new(ca.cert_forger(1024).expect("Failed to create cert forger"));
            let untrust = Arc::new(
                ca.untrust_cert_forger(256)
                    .expect("Failed to create untrust cert forger"),
            );
            tracing::info!("Cert forgers ready (trust: 1024, untrust: 256)");
            (Some(info), Some(forger), Some(untrust))
        }
        Err(err) => {
            tracing::warn!(
                event = "startup.ca.failed",
                error = %err,
                "CA initialization failed"
            );
            (None, None, None)
        }
    };

    let server_key_store = Arc::new(ServerKeyStore::new(&config.pki_dir));
    server_key_store.load_all_from_disk();
    let decision_engine = Arc::new(TlsDecisionEngine::new(
        &config.ssl_bypass_domains,
        Arc::clone(&server_key_store),
        EchTlsPolicy::default(),
        PinningConfig::default(),
    ));
    let decryption_mirror = Arc::new(DecryptionMirror::start(
        DecryptionMirrorConfig::default(),
        CancellationToken::new(),
    ));

    let tcp_session_tracker = TcpSessionTracker::new();


    let ct_observers = Arc::new(ObserverRegistry::default());

    let mut proto_reg = ProtoRegistry::new();

    proto_reg.register(Arc::new(TcpHandler::new(Arc::clone(&ct_observers))));
    proto_reg.register(Arc::new(UdpHandler::new(Arc::clone(&ct_observers))));
    proto_reg.register(Arc::new(IcmpHandler::v4()));
    proto_reg.register(Arc::new(IcmpHandler::v6()));

    let conntrack = Arc::new(Conntrack::new(Arc::new(proto_reg), ConntrackConfig::default()));

    // Test-only logger observer. Loguje każdy event conntrack na poziomie info.
    // Bug: handlery emit do `ct_observers`, core emit do wewnętrznego registry,
    // więc rejestrujemy ten sam logger w obu — bez tego connection lifecycle
    // (new/destroy) byłby niewidoczny przez ct_observers.
    struct LoggingCtObserver;

    impl CtObserver for LoggingCtObserver {
        fn on_new(&self, entry: &ConntrackEntry) {
            tracing::info!(
                event = "ct.observer.new",
                flow_id = entry.id,
                zone = entry.zone,
                proto = ?entry.original.protocol,
                src = %entry.original.src_ip,
                sport = entry.original.src_port,
                dst = %entry.original.dst_ip,
                dport = entry.original.dst_port,
                "ct entry confirmed"
            );
        }

        fn on_update(&self, entry: &ConntrackEntry, changed: CtStatus) {
            tracing::info!(
                event = "ct.observer.update",
                flow_id = entry.id,
                changed = ?changed,
                status = ?entry.status(),
                "ct entry updated"
            );
        }

        fn on_destroy(&self, entry: &ConntrackEntry, reason: DestroyReason) {
            tracing::info!(
                event = "ct.observer.destroy",
                flow_id = entry.id,
                reason = ?reason,
                bytes_orig = entry.bytes_orig.load(std::sync::atomic::Ordering::Relaxed),
                bytes_reply = entry.bytes_reply.load(std::sync::atomic::Ordering::Relaxed),
                packets_orig = entry.packets_orig.load(std::sync::atomic::Ordering::Relaxed),
                packets_reply = entry.packets_reply.load(std::sync::atomic::Ordering::Relaxed),
                "ct entry destroyed"
            );
        }

        fn on_anomaly(&self, entry: &ConntrackEntry, kind: AnomalyKind) {
            tracing::warn!(
                event = "ct.observer.anomaly",
                flow_id = entry.id,
                kind = ?kind,
                "ct anomaly"
            );
        }

        fn on_payload(&self, entry: &ConntrackEntry, dir: CtDirection, payload: &[u8]) {
            tracing::trace!(
                event = "ct.observer.payload",
                flow_id = entry.id,
                proto = ?entry.original.protocol,
                dir = ?dir,
                len = payload.len(),
                preview = %String::from_utf8_lossy(&payload[..payload.len().min(32)]),
                "ct payload chunk"
            );
        }
    }

    let ct_logger: Arc<dyn CtObserver> = Arc::new(LoggingCtObserver);
    ct_observers.register(Arc::clone(&ct_logger));         // handlery: payload, anomaly
    conntrack.register_observer(Arc::clone(&ct_logger));    // core: new, update, destroy
    tracing::info!(event = "ct.logger.registered", "conntrack debug observer attached");

    let _ct_reaper = Reaper::spawn(Arc::clone(&conntrack));

    let metrics_collector = Arc::new(metrics::MetricsCollector::new());
    let policy_provider = Arc::new(
        DiskPolicyProvider::from_loaded(&config)
            .await
            .expect("Failed to initialize policy provider"),
    );
    let netlink_cancel = CancellationToken::new();
    let netlink_listener = match NetlinkListener::new(netlink_cancel.clone()) {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(
                event = "startup.netlink_listener.failed",
                error = %err,
                "failed to initialize netlink listener"
            );
            return;
        }
    };

    let interface_monitor = Arc::new(
        NetworkInterfaceMonitor::new(netlink_cancel.clone(), &netlink_listener)
            .await
            .expect("Failed to initialize network interface monitor"),
    );
    let interface_controller = Arc::new(
        NetlinkInterfaceController::new().expect("Failed to initialize interface controller"),
    );
    
    let routing_table = match RoutingTable::new(&netlink_listener, netlink_cancel.clone()).await {
        Ok(table) => table,
        Err(err) => {
            tracing::error!(
                event = "startup.routing_table.failed",
                error = %err,
                "failed to initialize routing table"
            );
            return;
        }
    };
    let zones = Arc::new(crate::zones::provider::ZoneProvider::from_disk(&config).await);
    let zone_pairs = Arc::new(crate::zones::provider::ZonePairProvider::from_disk(&config).await);
    let zone_interfaces = Arc::new(crate::zones::provider::ZoneInterfaceProvider::from_disk(&config).await);

    // Startup VLAN reconciliation
    let loaded_zone_interfaces = zone_interfaces.get_zone_interfaces();
    let vlan_reconciler = Arc::new(crate::interfaces::VlanReconciler::new(Arc::clone(&interface_controller)));
    let startup_errors = vlan_reconciler
        .reconcile(&std::collections::HashMap::new(), &loaded_zone_interfaces)
        .await;
    if !startup_errors.is_empty() {
        tracing::warn!(errors = ?startup_errors, "startup VLAN reconciliation partial failures");
    }

    let zone_resolver = Arc::new(crate::zones::resolver::RoutingZoneResolver::new(
        Arc::clone(&zone_interfaces),
        Arc::clone(&zone_pairs),
        Arc::clone(&routing_table),
        Arc::clone(&interface_monitor),
    ));

    let smtp_policy_retriever = Arc::new(crate::dpi::smtp_policy_retriever::SmtpPolicyRetriever::new(
        Arc::clone(&zone_resolver),
        Arc::clone(&policy_provider),
    ));

    let smtp_tracker = Arc::new(crate::dpi::smtp::SmtpTracker::new(Arc::clone(&smtp_policy_retriever)));
    conntrack.register_observer(Arc::clone(&smtp_tracker) as Arc<dyn crate::conntrack::observer::CtObserver>);

    let loaded_policies = policy_provider.get_policies();
    let loaded_zones = zones.get_zones();
    let loaded_zone_pairs = zone_pairs.get_zone_pairs();
    let policy_engine = Arc::new(
        crate::policy::engine::PolicyEngine::from_policies(
            &loaded_policies,
            &loaded_zone_pairs,
        )
        .expect("Failed to initialize policy engine"),
    );
    tracing::info!(
        event = "startup.config_inventory.loaded",
        policy_count = loaded_policies.len(),
        zone_count = loaded_zones.len(),
        zone_pair_count = loaded_zone_pairs.len(),
        zone_interface_count = loaded_zone_interfaces.len(),
        "runtime config inventory loaded"
    );

    config_provider
        .register(Arc::clone(&policy_provider), "DiskPolicyProvider")
        .await;
    config_provider
        .register(Arc::clone(&zones), "ZoneProvider")
        .await;
    config_provider
        .register(Arc::clone(&zone_pairs), "ZonePairProvider")
        .await;
    config_provider
        .register(Arc::clone(&zone_interfaces), "ZoneInterfaceProvider")
        .await;

    tokio::spawn(events::init_event_system(config.event_socket_path.clone()));
    let mut sniffed_names = sniffed_interface_names(&loaded_zone_interfaces);

    if sniffed_names.is_empty() {
        if let Ok(env_ifaces) = std::env::var("CAPTURE_INTERFACES") {
            for name in env_ifaces.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                sniffed_names.push(name.to_string());
            }
            if !sniffed_names.is_empty() {
                tracing::warn!(
                    event = "sniffer.fallback.env",
                    interfaces = ?sniffed_names,
                    "no sniffed interfaces in zone_interfaces.json, using CAPTURE_INTERFACES env"
                );
            }
        }
    }

    let interface_ips = resolve_interface_ips(&sniffed_names);
    let local_ips = collect_local_ips(&interface_ips);
    let nat_store = Arc::new(NatConfigProvider::from_disk(config.data_dir.clone()).await);
    let nat_rules = match nat_store.get_config().to_runtime_rules() {
        Ok(rules) => rules,
        Err(err) => {
            tracing::error!(error = %err, "failed to build NAT rules from disk config");
            None
        }
    };

    tracing::info!(
        event = "startup.nat.loaded",
        has_nat_rules = nat_rules.is_some(),
        "NAT runtime rules loaded"
    );
    let nat_engine = NatEngine::new(nat_rules, interface_ips);

    // Late binding NatEngine ⇄ Conntrack: attach Weak ref + register observer
    // dla port_release on destroy.
    nat_engine.attach_conntrack(&conntrack);
    conntrack.register_observer(Arc::clone(&nat_engine) as Arc<dyn CtObserver>);

    // HelperRegistry — FtpHelper instaluje expectations dla data channel.
    let helpers = {
        let mut r = crate::conntrack::helper::HelperRegistry::new();
        r.register(Arc::new(crate::conntrack::helper::ftp::FtpHelper::new()));

        Arc::new(r)
    };

    // MASQUERADE flush: subskrypcja netlink → przy zmianie IP rebuild snapshot
    // i wywołanie replace_interface_ips. Conntrack flushuje stare entries.
    {
        let nat_engine_for_addr = Arc::clone(&nat_engine);
        let monitor_for_addr = Arc::clone(&interface_monitor);

        let mut rx = netlink_listener.subscribe();

        let cancel_for_addr = netlink_cancel.clone();

        tokio::spawn(async move {
            use netlink_packet_route::RouteNetlinkMessage;

            loop {
                tokio::select! {
                    _ = cancel_for_addr.cancelled() => break,

                    msg = rx.recv() => {
                        match msg {
                            Ok(RouteNetlinkMessage::NewAddress(_)) | Ok(RouteNetlinkMessage::DelAddress(_)) => {
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                                let snapshot = monitor_for_addr.snapshot();

                                let new_ips: HashMap<String, Vec<IpAddr>> = snapshot.into_iter()
                                    .map(|(name, iface)| {
                                        let ips: Vec<IpAddr> = iface.addresses.iter().map(|n| n.addr()).collect();
                                        (name, ips)
                                    }).collect();

                                nat_engine_for_addr.replace_interface_ips(new_ips);
                            }
                            Ok(_) => {}
                            Err(_) => {}
                        }
                    }
                }
            }
        });
    }

    // Inicjalizacja providera konfiguracji DNS inspection.
    let dns_inspection_store =
        Arc::new(DnsInspectionConfigProvider::from_disk(config.data_dir.clone()).await);

    let dns_initial_config = dns_inspection_store.get_config().clone();

    let dns_inspection = match DnsInspection::new((*dns_initial_config).clone()) {
        Ok(inspection) => inspection,
        Err(err) => {
            tracing::error!(
                event = "startup.dns_inspection.failed",
                error = %err,
                "failed to initialize DNS inspection"
            );
            return;
        }
    };

    let ips_store = Arc::new(IpsConfigProvider::from_disk(config.data_dir.clone()).await);
    let ips_initial_config = ips_store.get_config().clone();
    let ips = match Ips::new((*ips_initial_config).clone()) {
        Ok(inspection) => inspection,
        Err(err) => {
            tracing::error!(
                event = "startup.ips.failed",
                error = %err,
                "failed to initialize IPS"
            );
            return;
        }
    };

    let dpi_classifier = Arc::new(DpiClassifier::new());
    let identity_sessions = IdentitySessionStore::new_shared();

    let control_server = ControlServer::new(
        config.control_plane_socket_path.clone(),
        CancellationToken::new(),
    );
    tokio::spawn(control_server.serve());
    tracing::info!(
        event = "startup.control_server.spawned",
        socket = %config.control_plane_socket_path,
        "control server spawned"
    );

    // Rzutujemy DnsInspection na DnssecProvider i wstrzykujemy do PolicyEvalStage.
    let dnssec_provider: Arc<dyn DnssecProvider> =
        Arc::clone(&dns_inspection) as Arc<dyn DnssecProvider>;
    
    let ml_flow_stats = Arc::new(crate::ml::FlowStatsAggregator::new(
        std::time::Duration::from_secs(60),
    ));
    let ml_detector: Arc<dyn crate::ml::MlPacketInspector> =
        Arc::new(crate::ml::MlDetector::from_env());
    let pipeline_interface_monitor: Arc<dyn InterfaceMonitor> = interface_monitor.clone();

    let (exec_tx, exec_rx) = mpsc::unbounded_channel();

    let pipeline: DataPipeline<NetworkInterfaceMonitor> = DataPipeline {
        head: ValidationStage,
        tail: Chain {
            head: MetricsStage {
                collector: Arc::clone(&metrics_collector),
            },
            tail: Chain {
                head: LocalOwnershipStage {
                    config_provider: Arc::clone(&config_provider),
                    zone_interface_provider: Arc::clone(&zone_interfaces),
                    local_ips: Arc::new(local_ips.clone()),
                },
                tail: Chain {
                    head: IdentityLookupStage {
                        store: Arc::clone(&identity_sessions),
                    },
                    tail: Chain {
                        head: ConntrackInStage {
                            ct: Arc::clone(&conntrack),
                        },
                        tail: Chain {
                            head: DpiStage {
                                classifier: Arc::clone(&dpi_classifier),
                                flow_stats: Arc::clone(&ml_flow_stats),
                                pinning_detector: Some(decision_engine.pinning_detector_arc()),
                            },
                            tail: Chain {
                            head: TlsPortEnforcementStage {
                                config_provider: Arc::clone(&config_provider),
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
                                        head: DnsEchMitigationStage {
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
                                                    head: L4StateStage {
                                                        flow_stats: Arc::clone(&ml_flow_stats),
                                                    },
                                                    tail: Chain {
                                                        head: MlAlertStage::new(Arc::clone(&ml_detector)),
                                                        tail: Chain {
                                                            head: PolicyEvalStage {
                                                                policy_engine: Arc::clone(&policy_engine),
                                                                zone_resolver: Arc::clone(&zone_resolver),
                                                                dnssec: Some(dnssec_provider),
                                                            },
                                                            tail: Chain {
                                                                head: NatPostroutingStage {
                                                                    engine: Arc::clone(&nat_engine),
                                                                    routing_table: Arc::clone(&routing_table),
                                                                    interface_monitor: Arc::clone(&interface_monitor),
                                                                },
                                                                tail: Chain {
                                                                    head: FtpAlgStage {
                                                                        conntrack: Arc::clone(&conntrack),
                                                                        helpers: Arc::clone(&helpers),
                                                                    },
                                                                    tail: Chain {
                                                                        head: SmtpStage {
                                                                            tracker: Arc::clone(&smtp_tracker),
                                                                        },
                                                                        tail: Chain {
                                                                            head: ExecutionStage { tx: exec_tx.clone() },
                                                                            tail: ConntrackConfirmStage {
                                                                                ct: Arc::clone(&conntrack),
                                                                            },
                                                                        }
                                                                    }
                                                                },
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        },
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

    if config.ssl_inspection_enabled {
        let tls_runtime_cancel = CancellationToken::new();
        decision_engine.spawn_maintenance_task(tls_runtime_cancel.clone());

        match (&tls_cert_forger, &tls_untrust_forger) {
            (Some(forger), Some(untrust)) => {
                let listen_addr = config
                    .mitm_listen_addr
                    .parse()
                    .expect("MITM_LISTEN_ADDR must be a valid socket address");

                match TransparentRedirect::new(
                    listen_addr,
                    sniffed_names.clone(),
                    config.tls_inspection_ports.clone(),
                    local_ips.iter().copied().collect(),
                )
                .and_then(|redirect| redirect.install())
                {
                    Ok(()) => {
                        tracing::info!(
                            event = "startup.tls_redirect.installed",
                            listen_addr = %listen_addr,
                            ports = ?config.tls_inspection_ports,
                            interfaces = ?sniffed_names,
                            "TLS transparent redirect installed"
                        );
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to install TLS transparent redirect");
                    }
                }

                let proxy_config = MitmProxyConfig {
                    listen_addr,
                    cert_forger: Arc::clone(forger),
                    untrust_forger: Arc::clone(untrust),
                    decision_engine: Arc::clone(&decision_engine),
                    decrypted_inspector: Arc::new(DecryptedChainInspector::with_identity_and_routing(
                        pipeline.clone(),
                        Arc::clone(&dpi_classifier),
                        Arc::clone(&identity_sessions),
                        crate::tls::decrypted_chain::DecryptedRoutingContext {
                            interface_monitor: Arc::clone(&pipeline_interface_monitor),
                            zone_interface_store: Arc::clone(&zone_interfaces),
                        },
                    )),
                    decryption_mirror: Arc::clone(&decryption_mirror),
                    cancel: tls_runtime_cancel,
                };

                match MitmProxy::bind(proxy_config).await {
                    Ok(proxy) => {
                        tokio::spawn(proxy.serve());
                        tracing::info!(
                            event = "startup.mitm_proxy.spawned",
                            listen_addr = %listen_addr,
                            "SSL/TLS inspection enabled"
                        );
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

    let tun = TunForwarder::new(&config);
    config_provider
        .register(Arc::clone(&tun), "TunForwarder")
        .await;

    tokio::spawn(ExecutionSink::new(Arc::clone(&tun), Arc::clone(&metrics_collector), exec_rx).run());
    tracing::info!(
        event = "startup.execution_sink.spawned",
        "execution sink spawned"
    );

    let (sniffer, mut raw_rx) = InterfaceSniffer::with_sniffing(config.pcap_timeout_ms);
    let sniffer = Arc::new(sniffer);
    
    // Startup sniffer reconciliation
    tracing::info!(
        event = "sniffer.reconcile.start",
        interfaces = ?sniffed_names,
        "starting capture on interfaces"
    );
    sniffer.reconcile_capture_interfaces(&sniffed_names);
    
    config_provider
        .register(Arc::clone(&sniffer), "InterfaceSniffer")
        .await;

    // QueryHandler construction moved here to have access to both vlan_reconciler and sniffer
    let query_server = QueryServer::<DiskPolicyProvider, NetworkInterfaceMonitor, NetlinkInterfaceController>::new(
        QueryHandler {
            conntrack: Arc::clone(&conntrack),
            tcp_tracker: Arc::clone(&tcp_session_tracker),
            nat_engine: Arc::clone(&nat_engine),
            nat_store: Arc::clone(&nat_store),
            policy_store: Arc::clone(&policy_provider),
            policy_engine: Arc::clone(&policy_engine),
            zone_store: zones,
            zone_pair_store: Arc::clone(&zone_pairs),
            zone_interface_store: Arc::clone(&zone_interfaces),
            config_provider: Arc::clone(&config_provider),
            dns_inspection_store: Arc::clone(&dns_inspection_store),
            dns_inspection: Arc::clone(&dns_inspection),
            ips_store: Arc::clone(&ips_store),
            ips: Arc::clone(&ips),
            decision_engine: Arc::clone(&decision_engine),
            decryption_mirror: Arc::clone(&decryption_mirror),
            server_key_store: Arc::clone(&server_key_store),
            pinning_detector: decision_engine.pinning_detector_arc(),
            interface_monitor: Arc::clone(&interface_monitor),
            interface_controller: Arc::clone(&interface_controller),
            vlan_reconciler,
            interface_sniffer: Arc::clone(&sniffer),
            metrics_collector: Arc::clone(&metrics_collector),
            reset_lock: Arc::new(Mutex::new(())),
        },
        Arc::clone(&identity_sessions),
        &config.query_socket_path,
        CancellationToken::new(),
    );
    tokio::spawn(query_server.serve());
    tracing::info!(
        event = "startup.query_server.spawned",
        socket = %config.query_socket_path,
        "query server spawned"
    );
    let server_cert_server = server_certificate_server::ServerCertificateServer::new(
        server_certificate_server::ServerCertificateHandler {
            server_key_store: Arc::clone(&server_key_store),
        },
        &config.server_cert_socket_path,
        CancellationToken::new(),
    );
    tokio::spawn(server_cert_server.serve());
    tracing::info!(
        event = "startup.server_certificate_server.spawned",
        socket = %config.server_cert_socket_path,
        "server certificate server spawned"
    );

    tracing::info!(
        event = "pipeline.loop.start",
        sniffed_interfaces = ?sniffed_names,
        "entering packet processing loop"
    );

    let pkt_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));

    while let Some(raw_packet) = raw_rx.recv().await {
        if let Some(mut ctx) = defrag.process_raw(raw_packet) {
            let pipeline = pipeline.clone();
            let tun = Arc::clone(&tun);
            let metrics_collector = Arc::clone(&metrics_collector);
            let counter = Arc::clone(&pkt_counter);
            let exec_tx = exec_tx.clone();

            tokio::spawn(async move {
                if !matches!(
                    &ctx.borrow_sliced_packet().net,
                    Some(NetSlice::Ipv4(_) | NetSlice::Ipv6(_))
                ) {
                    return;
                }

                let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if n == 1 || n % 1000 == 0 {
                    tracing::info!(event = "pipeline.packet.tick", count = n, "pipeline processed packet");
                }

                let result: StageOutcome = pipeline.process(&mut ctx, &exec_tx).await;

                if matches!(result, StageOutcome::Continue) {
                    tun.forward(&ctx).await;
                } else {
                    metrics_collector.observe_drop();
                }
            });
        }
    }
}

fn sniffed_interface_names<S: std::hash::BuildHasher>(
    loaded_zone_interfaces: &HashMap<crate::zones::ZoneInterfaceId, crate::zones::ZoneInterface, S>,
) -> Vec<String> {
    loaded_zone_interfaces
        .iter()
        .filter(|(_, zi)| zi.sniffed)
        .filter_map(|(id, _)| crate::zones::resolve_os_name(loaded_zone_interfaces, id))
        .collect()
}

fn resolve_interface_ips(capture_interfaces: &[String]) -> HashMap<String, Vec<IpAddr>> {
    let mut interface_ips = HashMap::new();

    match Device::list() {
        Ok(devices) => {
            for iface in capture_interfaces {
                let ips = devices
                    .iter()
                    .find(|device| device.name == *iface)
                    .map(|device| device.addresses.iter().map(|addr| addr.addr).collect())
                    .unwrap_or_default();
                interface_ips.insert(iface.clone(), ips);
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to enumerate interface addresses");
            for iface in capture_interfaces {
                interface_ips.insert(iface.clone(), Vec::new());
            }
        }
    }

    interface_ips
}

fn collect_local_ips(interface_ips: &HashMap<String, Vec<IpAddr>>) -> HashSet<IpAddr> {
    interface_ips
        .values()
        .flat_map(|ips| ips.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zones::{
        InterfaceStatus, PhysicalInterface, ZoneId, ZoneInterface, ZoneInterfaceId, ZoneInterfaceKind,
    };
    use std::collections::HashMap;
    use uuid::Uuid;

    fn zone_interface_id(value: u128) -> ZoneInterfaceId {
        ZoneInterfaceId::from(Uuid::from_u128(value))
    }

    fn zone_id(value: u128) -> ZoneId {
        ZoneId::from(Uuid::from_u128(value))
    }

    fn physical_zone_interface(name: &str, sniffed: bool) -> ZoneInterface {
        ZoneInterface {
            zone_id: zone_id(1),
            kind: ZoneInterfaceKind::Physical(PhysicalInterface {
                interface_name: name.to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed,
        }
    }

    #[test]
    fn sniffed_interface_names_resolves_configured_interfaces() {
        let mut interfaces = HashMap::new();
        interfaces.insert(zone_interface_id(1), physical_zone_interface("eth1", true));
        interfaces.insert(zone_interface_id(2), physical_zone_interface("eth2", true));
        interfaces.insert(zone_interface_id(3), physical_zone_interface("eth3", false));

        let mut names = sniffed_interface_names(&interfaces);
        names.sort();

        assert_eq!(names, vec!["eth1".to_string(), "eth2".to_string()]);
    }
}
