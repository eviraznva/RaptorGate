mod config;
mod control_server;
mod data_plane;
mod disk_store;
mod dpi;
mod events;
mod identity;
mod ip_defrag;
mod logging;
mod packet_validator;
mod pipeline;
mod policy;
mod proto;
mod query_server;
mod rule_tree;
mod server_certificate_server;
mod tls;
mod zones;
mod swapper;
mod integrity;

use crate::config::provider::AppConfigProvider;
use crate::control_server::ControlServer;
use crate::data_plane::dns_inspection::dns_inspection::DnsInspection;
use crate::data_plane::dns_inspection::dnssec::DnssecProvider;
use crate::data_plane::dns_inspection::provider::DnsInspectionConfigProvider;
use crate::data_plane::interface_sniffer::InterfaceSniffer;
use crate::data_plane::ips::ips::Ips;
use crate::data_plane::ips::provider::IpsConfigProvider;
use crate::data_plane::nat::{NatConfigProvider, NatEngine};
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::data_plane::tun_forwarder::TunForwarder;
use crate::dpi::DpiClassifier;
use crate::identity::{IdentityEnforcementConfig, IdentitySessionStore};
use crate::ip_defrag::{DefragConfig, IpDefragEngine};
use crate::pipeline::wrappers::{
    DnsBlockListStage, DnsEchMitigationStage, DnsTunnelingStage, DpiStage, FtpAlgStage,
    IdentityLookupStage, IpsStage, LocalOwnershipStage, NatPostroutingStage, NatPreroutingStage,
    PolicyEvalStage, TcpClassificationStage, TlsPortEnforcementStage, ValidationStage,
};
use crate::pipeline::{Chain, Stage, StageOutcome};
use crate::policy::provider::DiskPolicyProvider;
use crate::query_server::{QueryHandler, QueryServer};
use crate::tls::{
    CaManager, DecryptedChainInspector, EchTlsPolicy, MitmProxy, MitmProxyConfig,
    PinningConfig, ServerKeyStore, TlsDecisionEngine, TransparentRedirect,
};
use etherparse::NetSlice;
use pcap::Device;
use std::collections::{HashMap, HashSet};
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
            LocalOwnershipStage,
            Chain<
                IdentityLookupStage,
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
                                                TcpClassificationStage,
                                                Chain<PolicyEvalStage, Chain<NatPostroutingStage, FtpAlgStage>>,
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
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .json()
            .flatten_event(true)
            .init();
    }

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
        capture_interfaces = ?config.capture_interfaces,
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

    let tcp_session_tracker = TcpSessionTracker::new();
    let policy_provider = Arc::new(
        DiskPolicyProvider::from_loaded(&config)
            .await
            .expect("Failed to initialize policy provider"),
    );
    let zones = Arc::new(crate::zones::provider::ZoneProvider::from_disk(&config).await);
    let zone_pairs = Arc::new(crate::zones::provider::ZonePairProvider::from_disk(&config).await);
    let zone_interfaces = Arc::new(crate::zones::provider::ZoneInterfaceProvider::from_disk(&config).await);

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
    let interface_ips = resolve_interface_ips(&config.capture_interfaces);
    let local_ips = collect_local_ips(&interface_ips);
    let nat_store = Arc::new(NatConfigProvider::from_disk(config.data_dir.clone()).await);
    let nat_rules = match nat_store.get_config().to_runtime_rules() {
        Ok(rules) => rules,
        Err(err) => {
            tracing::error!(error = %err, "failed to build NAT rules from disk config");
            None
        }
    };
    let nat_engine = Arc::new(Mutex::new(NatEngine::new(&nat_rules, interface_ips)));

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

    // Runtime store aktywnych sesji identity (ADR 0002), dzielony z handlerem gRPC i pipeline.
    let identity_sessions = IdentitySessionStore::new_shared();

    let query_server = QueryServer::<DiskPolicyProvider>::new(
        QueryHandler {
            tcp_tracker: Arc::clone(&tcp_session_tracker),
            nat_engine: Arc::clone(&nat_engine),
            nat_store: Arc::clone(&nat_store),
            policy_store: Arc::clone(&policy_provider),
            zone_store: zones,
            zone_pair_store: zone_pairs,
            zone_interface_store: Arc::clone(&zone_interfaces),
            config_provider: Arc::clone(&config_provider),
            dns_inspection_store: Arc::clone(&dns_inspection_store),
            dns_inspection: Arc::clone(&dns_inspection),
            ips_store: Arc::clone(&ips_store),
            ips: Arc::clone(&ips),
            decision_engine: Arc::clone(&decision_engine),
            server_key_store: Arc::clone(&server_key_store),
            pinning_detector: decision_engine.pinning_detector_arc(),
        },
        Arc::clone(&identity_sessions),
        &config.query_socket_path,
        CancellationToken::new(),
    );
    tokio::spawn(query_server.serve());
    let server_cert_server = server_certificate_server::ServerCertificateServer::new(
        server_certificate_server::ServerCertificateHandler {
            server_key_store: Arc::clone(&server_key_store),
        },
        &config.server_cert_socket_path,
        CancellationToken::new(),
    );
    tokio::spawn(server_cert_server.serve());

    let control_server = ControlServer::new(
        config.control_plane_socket_path.clone(),
        CancellationToken::new(),
    );
    tokio::spawn(control_server.serve());

    // Rzutujemy DnsInspection na DnssecProvider i wstrzykujemy do PolicyEvalStage.
    let dnssec_provider: Arc<dyn DnssecProvider> =
        Arc::clone(&dns_inspection) as Arc<dyn DnssecProvider>;

    let identity_enforcement = match identity_enforcement_from_env() {
        Ok(enforcement) => Arc::new(enforcement),
        Err(err) => {
            tracing::error!(
                event = "startup.identity_enforcement.failed",
                error = %err,
                "failed to initialize identity enforcement"
            );
            return;
        }
    };

    let pipeline = DataPipeline {
        head: ValidationStage,
        tail: Chain {
            head: LocalOwnershipStage {
                config_provider: Arc::clone(&config_provider),
                local_ips: Arc::new(local_ips),
            },
            tail: Chain {
                head: IdentityLookupStage {
                    store: Arc::clone(&identity_sessions),
                },
                tail: Chain {
                    head: DpiStage {
                        classifier: Arc::clone(&dpi_classifier),
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
                                                head: TcpClassificationStage {
                                                    tracker: Arc::clone(&tcp_session_tracker),
                                                },
                                                tail: Chain {
                                                    head: PolicyEvalStage {
                                                        provider: Arc::clone(&policy_provider),
                                                        dnssec: Some(dnssec_provider),
                                                        identity_enforcement: Arc::clone(&identity_enforcement),
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
                    config.capture_interfaces.clone(),
                    config.tls_inspection_ports.clone(),
                )
                .and_then(|redirect| redirect.install())
                {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to install TLS transparent redirect");
                    }
                }

                let proxy_config = MitmProxyConfig {
                    listen_addr,
                    cert_forger: Arc::clone(forger),
                    untrust_forger: Arc::clone(untrust),
                    decision_engine: Arc::clone(&decision_engine),
                    decrypted_inspector: Arc::new(DecryptedChainInspector::with_identity(
                        pipeline.clone(),
                        Arc::clone(&dpi_classifier),
                        Arc::clone(&identity_sessions),
                        Arc::clone(&identity_enforcement),
                    )),
                    cancel: tls_runtime_cancel,
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
        tracing::error!(
            event = "startup.sniffer.failed",
            error = %e,
            "interface sniffer error"
        );
    }

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

fn identity_enforcement_from_env() -> anyhow::Result<IdentityEnforcementConfig> {
    let raw = std::env::var("IDENTITY_REQUIRED_SRC_CIDRS")
        .unwrap_or_else(|_| "192.168.10.0/24".into());
    let cidrs = raw
        .split(',')
        .map(str::trim)
        .filter(|cidr| !cidr.is_empty())
        .map(|cidr| {
            cidr.parse().map_err(|err| {
                anyhow::anyhow!("invalid IDENTITY_REQUIRED_SRC_CIDRS entry '{cidr}': {err}")
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(IdentityEnforcementConfig::new(cidrs))
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
