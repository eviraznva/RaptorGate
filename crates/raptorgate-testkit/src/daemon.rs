use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use ngfw::conntrack::config::ConntrackConfig;
use ngfw::conntrack::helper::HelperRegistry;
use ngfw::conntrack::observer::ObserverRegistry;
use ngfw::conntrack::proto::icmp::IcmpHandler;
use ngfw::conntrack::proto::tcp::TcpHandler;
use ngfw::conntrack::proto::udp::UdpHandler;
use ngfw::conntrack::proto::ProtoRegistry;
use ngfw::conntrack::table::Conntrack;
use ngfw::config::provider::AppConfigProvider;
use ngfw::config::AppConfig;
use ngfw::conntrack::session_manager::SessionManager;
use ngfw::daemon::{Daemon, DaemonDeps, DaemonV2, ProcessOutput, StaticDeps};
use ngfw::data_plane::dns_inspection::dns_inspection::DnsInspection;
use ngfw::data_plane::dns_inspection::config::DnsInspectionConfig;
use ngfw::data_plane::ips::config::IpsConfig;
use ngfw::data_plane::ips::ips::Ips;
use ngfw::SingleDiskStore;
use ngfw::dpi::smtp::SmtpTracker;
use ngfw::dpi::smtp_policy_retriever::SmtpPolicyRetriever;
use ngfw::dpi::DpiClassifier;
use ngfw::identity::IdentitySessionStore;
use ngfw::ip_defrag::{DefragConfig, IpDefragEngine};
use ngfw::metrics::MetricsCollector;
use ngfw::ml::{FlowStatsAggregator, MlDetector, MlPacketInspector};
use ngfw::interfaces::InterfaceMonitor;
use ngfw::nat::NatEngine;
use ngfw::nat::config::NatRules;
use ngfw::netlink::routing_table::{RouteEntry, RoutingTable};
use ngfw::policy::engine::PolicyEngine;
use ngfw::policy::provider::DiskPolicyProvider;
use ngfw::policy::{Policy, PolicyId};
use ngfw::interfaces::NetworkInterfaceMonitor;
use ngfw::proto::services::ConfigBundle;
use ngfw::tls::{EchTlsPolicy, PinningConfig, ServerKeyStore, TlsDecisionEngine};
use ngfw::zones::provider::{ZoneInterfaceProvider, ZonePairProvider, ZoneProvider};
use ngfw::zones::resolver::RoutingZoneResolver;
use ngfw::zones::{Zone, ZoneInterface, ZonePair};
use tempfile::TempDir;
use thiserror::Error;

use crate::static_infra::{iface_eth, static_monitor_from_pairs};

fn ensure_test_daemon_app_paths(cfg: &mut AppConfig, temp: &Path, data_dir: &Path) {
    let pki_dir = temp.join("pki");
    cfg.data_dir = data_dir.to_path_buf();
    cfg.event_socket_path = temp.join("evt.sock").to_string_lossy().into_owned();
    cfg.query_socket_path = temp.join("qry.sock").to_string_lossy().into_owned();
    cfg.pki_dir = pki_dir.to_string_lossy().into_owned();
    cfg.control_plane_socket_path = temp.join("ctl.sock").to_string_lossy().into_owned();
    cfg.server_cert_socket_path = temp.join("srv.sock").to_string_lossy().into_owned();
}

pub struct TestDeps {
    pub metrics_collector: Arc<MetricsCollector>,
    pub config_provider: Arc<AppConfigProvider<SingleDiskStore<AppConfig>>>,
    pub zone_interfaces: Arc<ZoneInterfaceProvider>,
    pub local_ips: Arc<HashSet<IpAddr>>,
    pub identity_sessions: Arc<IdentitySessionStore>,
    pub conntrack: Arc<Conntrack>,
    pub dpi_classifier: Arc<DpiClassifier>,
    pub ml_flow_stats: Arc<FlowStatsAggregator>,
    pub decision_engine: Arc<TlsDecisionEngine>,
    pub dns_inspection: Arc<DnsInspection>,
    pub ips: Arc<Ips>,
    pub nat_engine: Arc<NatEngine>,
    pub ml_detector: Arc<dyn MlPacketInspector>,
    pub policy_engine: Arc<PolicyEngine>,
    pub zone_resolver: Arc<RoutingZoneResolver<NetworkInterfaceMonitor>>,
    pub routing_table: Arc<RoutingTable>,
    pub interface_monitor: Arc<NetworkInterfaceMonitor>,
    pub helpers: Arc<HelperRegistry>,
    pub smtp_tracker: Arc<SmtpTracker>,
}

impl DaemonDeps for TestDeps {
    type ConfigStore = SingleDiskStore<AppConfig>;
    type IfaceMon = NetworkInterfaceMonitor;
    type Routes = RoutingTable;
    type Dnssec = DnsInspection;

    fn static_dependencies(&self) -> StaticDeps<'_, Self> {
        StaticDeps {
            metrics_collector: &self.metrics_collector,
            config_provider: &self.config_provider,
            zone_interfaces: &self.zone_interfaces,
            local_ips: &self.local_ips,
            identity_sessions: &self.identity_sessions,
            conntrack: &self.conntrack,
            dpi_classifier: &self.dpi_classifier,
            ml_flow_stats: &self.ml_flow_stats,
            decision_engine: &self.decision_engine,
            dns_inspection: &self.dns_inspection,
            policy_dnssec: &self.dns_inspection,
            ips: &self.ips,
            nat_engine: &self.nat_engine,
            ml_detector: &self.ml_detector,
            policy_engine: &self.policy_engine,
            zone_resolver: &self.zone_resolver,
            routing_table: &self.routing_table,
            interface_monitor: &self.interface_monitor,
            helpers: &self.helpers,
            smtp_tracker: &self.smtp_tracker,
        }
    }
}

#[derive(Error, Debug)]
pub enum TestDaemonBuildError {
    #[error("bundle parse/validate: {0}")]
    Bundle(#[from] anyhow::Error),
    #[error("DNS inspection: {0}")]
    Dns(String),
    #[error("IPS: {0}")]
    Ips(String),
    #[error("policy engine: {0}")]
    PolicyEngine(#[from] ngfw::policy::engine::PolicyEngineError),
}

fn parse_bundle(
    bundle: ConfigBundle,
) -> anyhow::Result<(
    HashMap<PolicyId, Policy>,
    Vec<(ngfw::zones::ZoneId, Zone)>,
    Vec<(ngfw::zones::ZonePairId, ZonePair)>,
    Vec<(ngfw::zones::ZoneInterfaceId, ZoneInterface)>,
    Vec<ngfw::proto::config::NatRule>,
    Option<ngfw::proto::config::AppConfig>,
)> {
    let ConfigBundle {
        rules,
        zones,
        zone_pairs,
        zone_interfaces,
        nat_rules,
        app_config,
        ..
    } = bundle;

    let policies: HashMap<PolicyId, Policy> = rules
        .into_iter()
        .map(Policy::try_from_rule)
        .collect::<Result<_, _>>()?;

    let zones: Vec<(ngfw::zones::ZoneId, Zone)> = zones
        .into_iter()
        .map(Zone::try_from_proto)
        .collect::<Result<_, _>>()?;

    let zone_pairs: Vec<(ngfw::zones::ZonePairId, ZonePair)> = zone_pairs
        .into_iter()
        .map(ZonePair::try_from_proto)
        .collect::<Result<_, _>>()?;

    let zone_interfaces: Vec<(ngfw::zones::ZoneInterfaceId, ZoneInterface)> = zone_interfaces
        .into_iter()
        .map(ZoneInterface::try_from_proto)
        .collect::<Result<_, _>>()?;

    Ok((
        policies,
        zones,
        zone_pairs,
        zone_interfaces,
        nat_rules,
        app_config,
    ))
}

pub struct TestDaemon {
    daemon_v2: Arc<DaemonV2<TestDeps>>,
    deps: Arc<TestDeps>,
    _temp: Arc<TempDir>,
}

impl TestDaemon {
    pub fn builder() -> TestDaemonBuilder {
        TestDaemonBuilder::new()
    }

    pub fn daemon(&self) -> &Daemon<TestDeps> {
        self.daemon_v2.daemon()
    }

    pub fn deps(&self) -> &Arc<TestDeps> {
        &self.deps
    }

    pub fn sessions(&self) -> &Arc<SessionManager> {
        self.daemon_v2.sessions()
    }

    pub fn conntrack_snapshot(&self) -> Vec<ngfw::conntrack::table::ConntrackFlowSnapshot> {
        self.deps
            .conntrack
            .metrics()
            .snapshot_flows(None, true)
    }

    pub async fn process_raw(&self, raw: Vec<u8>, iface: Arc<str>) -> ProcessOutput {
        Box::pin(self.daemon_v2.process_raw(raw, iface)).await
    }
}

pub struct TestDaemonBuilder {
    bundle: Option<ConfigBundle>,
}

impl Default for TestDaemonBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestDaemonBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self { bundle: None }
    }

    #[must_use] 
    pub fn with_bundle(mut self, bundle: ConfigBundle) -> Self {
        self.bundle = Some(bundle);
        self
    }

    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::missing_errors_doc)]
    #[allow(clippy::too_many_lines)]
    pub async fn build(self) -> Result<TestDaemon, TestDaemonBuildError> {
        let bundle = self
            .bundle
            .unwrap_or_else(|| crate::config_bundle::ConfigBundleBuilder::new().build());
        let (policies, zones, zone_pairs, zone_interfaces, nat_rules, bundle_app_config) =
            parse_bundle(bundle)?;
        let temp = Arc::new(tempfile::tempdir().map_err(anyhow::Error::from)?);
        let data_dir = temp.path().join("data");
        tokio::fs::create_dir_all(&data_dir).await.map_err(anyhow::Error::from)?;

        let app_config_store_dir = temp.path().join("app_cfg");
        tokio::fs::create_dir_all(&app_config_store_dir)
            .await
            .map_err(anyhow::Error::from)?;

        let pki_dir = temp.path().join("pki");
        tokio::fs::create_dir_all(&pki_dir).await.map_err(anyhow::Error::from)?;

        let mut app_config = if let Some(proto_cfg) = bundle_app_config {
            AppConfig::from_proto(proto_cfg)?
        } else {
            AppConfig {
                pcap_timeout_ms: 3000,
                tun_device_name: "tun0".into(),
                tun_address: "10.254.254.1".parse().unwrap(),
                tun_netmask: "255.255.255.0".parse().unwrap(),
                data_dir: data_dir.clone(),
                event_socket_path: String::new(),
                query_socket_path: String::new(),
                dev_config: None,
                pki_dir: String::new(),
                ssl_inspection_enabled: false,
                mitm_listen_addr: "127.0.0.1:8443".into(),
                control_plane_socket_path: String::new(),
                server_cert_socket_path: String::new(),
                ssl_bypass_domains: vec![],
                tls_inspection_ports: vec![443],
                block_tls_on_undeclared_ports: false,
            }
        };
        ensure_test_daemon_app_paths(&mut app_config, temp.path(), &data_dir);

        let app_store = SingleDiskStore::new("app_config", app_config_store_dir.clone());
        app_store
            .save(app_config.clone())
            .await
            .map_err(anyhow::Error::from)?;
        let config_provider = Arc::new(AppConfigProvider::with_store_and_config(
            app_store,
            app_config.clone(),
        ));

        NatRules::try_from_proto(ngfw::proto::config::NatRuleSet {
            items: nat_rules.clone(),
        })
        .map_err(|e| anyhow::anyhow!("nat: {e}"))?;

        let zone_map: HashMap<_, _> = zones.iter().cloned().collect();
        let pair_map: HashMap<_, _> = zone_pairs.iter().cloned().collect();
        let zi_map: HashMap<_, _> = zone_interfaces.iter().cloned().collect();

        let errors = ngfw::validation::validate_bundle(
            &policies,
            &pair_map,
            &zone_map,
            &zi_map,
        );
        if !errors.is_empty() {
            let msg = errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ");
            return Err(TestDaemonBuildError::Bundle(anyhow::anyhow!(
                "bundle integrity: {msg}"
            )));
        }

        let zone_store = Arc::new(ZoneProvider::from_disk(&app_config).await);
        zone_store
            .swap_zones(zones)
            .await
            .map_err(anyhow::Error::from)?;

        let zone_interface_store = Arc::new(ZoneInterfaceProvider::from_disk(&app_config).await);
        zone_interface_store
            .swap_zone_interfaces(zone_interfaces)
            .await
            .map_err(anyhow::Error::from)?;

        let zone_pair_store = Arc::new(ZonePairProvider::from_disk(&app_config).await);
        zone_pair_store
            .swap_zone_pairs(zone_pairs)
            .await
            .map_err(anyhow::Error::from)?;

        let policy_store = Arc::new(DiskPolicyProvider::from_policies(
            policies.clone(),
            data_dir.clone(),
        ));

        let policy_engine = Arc::new(PolicyEngine::from_policies(
            &policy_store.get_policies(),
            &zone_pair_store.get_zone_pairs(),
        )?);

        let interface_monitor = static_monitor_from_pairs([
            iface_eth("eth1", 10, "192.168.10.254/24"),
            iface_eth("eth2", 11, "192.168.20.254/24"),
        ]);

        let routes = vec![
            RouteEntry {
                destination: "192.168.20.0/24".parse().unwrap(),
                out_interface_index: ngfw::interfaces::SystemInterfaceId::from(11u32),
                priority: 100,
            },
            RouteEntry {
                destination: "192.168.10.0/24".parse().unwrap(),
                out_interface_index: ngfw::interfaces::SystemInterfaceId::from(10u32),
                priority: 100,
            },
            RouteEntry {
                destination: "0.0.0.0/0".parse().unwrap(),
                out_interface_index: ngfw::interfaces::SystemInterfaceId::from(11u32),
                priority: 200,
            },
        ];
        let routing_table = RoutingTable::from_static_routes(routes);

        let zone_resolver = Arc::new(RoutingZoneResolver::new(
            Arc::clone(&zone_interface_store),
            Arc::clone(&zone_pair_store),
            Arc::clone(&routing_table),
            Arc::clone(&interface_monitor),
        ));

        let mut interface_ips: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for (_, iface) in interface_monitor.snapshot() {
            interface_ips.insert(
                iface.name.clone(),
                iface.addresses.iter().map(|n| n.addr()).collect(),
            );
        }
        let local_ips: HashSet<IpAddr> = interface_ips.values().flatten().copied().collect();

        let nat_engine = NatEngine::new(None, interface_ips);

        let dns_inspection =
            DnsInspection::new(DnsInspectionConfig::default()).map_err(|e| TestDaemonBuildError::Dns(e.to_string()))?;
        let ips = Ips::new(IpsConfig::default()).map_err(|e| TestDaemonBuildError::Ips(e.to_string()))?;

        let server_key_store = Arc::new(ServerKeyStore::new(&app_config.pki_dir));
        let decision_engine = Arc::new(TlsDecisionEngine::new(
            &app_config.ssl_bypass_domains,
            Arc::clone(&server_key_store),
            EchTlsPolicy::default(),
            PinningConfig::default(),
        ));

        let ct_observers = Arc::new(ObserverRegistry::default());
        let mut proto_reg = ProtoRegistry::new();
        proto_reg.register(Arc::new(TcpHandler::new(Arc::clone(&ct_observers))));
        proto_reg.register(Arc::new(UdpHandler::new(Arc::clone(&ct_observers))));
        proto_reg.register(Arc::new(IcmpHandler::v4()));
        proto_reg.register(Arc::new(IcmpHandler::v6()));

        let conntrack = Arc::new(Conntrack::new(
            Arc::new(proto_reg),
            ConntrackConfig::default(),
        ));
        nat_engine.attach_conntrack(&conntrack);
        conntrack.register_observer(Arc::clone(&nat_engine) as Arc<dyn ngfw::conntrack::observer::CtObserver>);

        let smtp_policy_retriever = Arc::new(SmtpPolicyRetriever::new(
            Arc::clone(&zone_resolver),
            Arc::clone(&policy_store),
        ));
        let smtp_tracker = Arc::new(SmtpTracker::new(Arc::clone(&smtp_policy_retriever)));
        conntrack.register_observer(Arc::clone(&smtp_tracker) as Arc<dyn ngfw::conntrack::observer::CtObserver>);

        let helpers = {
            let mut r = HelperRegistry::new();
            r.register(Arc::new(ngfw::conntrack::helper::ftp::FtpHelper::new()));
            Arc::new(r)
        };

        let metrics_collector = Arc::new(MetricsCollector::new());
        let dpi_classifier = Arc::new(DpiClassifier::new());
        let identity_sessions = IdentitySessionStore::new_shared();
        let ml_flow_stats = Arc::new(FlowStatsAggregator::new(std::time::Duration::from_secs(60)));
        let ml_detector: Arc<dyn MlPacketInspector> = Arc::new(MlDetector::from_env());

        //TODO: we should reuse bundle verifying logic
        config_provider
            .register(Arc::clone(&policy_store), "DiskPolicyProvider")
            .await;
        config_provider
            .register(Arc::clone(&zone_store), "ZoneProvider")
            .await;
        config_provider
            .register(Arc::clone(&zone_pair_store), "ZonePairProvider")
            .await;
        config_provider
            .register(Arc::clone(&zone_interface_store), "ZoneInterfaceProvider")
            .await;

        let deps = Arc::new(TestDeps {
            metrics_collector,
            config_provider,
            zone_interfaces: zone_interface_store,
            local_ips: Arc::new(local_ips),
            identity_sessions,
            conntrack,
            dpi_classifier,
            ml_flow_stats,
            decision_engine,
            dns_inspection,
            ips,
            nat_engine,
            ml_detector,
            policy_engine,
            zone_resolver,
            routing_table,
            interface_monitor,
            helpers,
            smtp_tracker,
        });

        let (exec_tx, exec_rx) = tokio::sync::mpsc::unbounded_channel();
        let defrag = IpDefragEngine::new(DefragConfig::default());
        let daemon_v2 = DaemonV2::assemble_v2(deps.clone(), defrag, exec_tx, Some(exec_rx));

        Ok(TestDaemon {
            daemon_v2,
            deps,
            _temp: temp,
        })
    }
}
