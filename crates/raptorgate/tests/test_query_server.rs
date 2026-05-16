use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use ngfw::config::provider::AppConfigProvider;
use ngfw::data_plane::dns_inspection::dns_inspection::DnsInspection;
use ngfw::data_plane::dns_inspection::provider::DnsInspectionConfigProvider;
use ngfw::data_plane::ips::ips::Ips;
use ngfw::data_plane::ips::provider::IpsConfigProvider;
use ngfw::nat::{NatConfigProvider, NatEngine};
use ngfw::data_plane::tcp_session_tracker::TcpSessionTracker;
use ngfw::identity::IdentitySessionStore;
use ngfw::policy::provider::DiskPolicyProvider;
use ngfw::proto::config::{AppConfig as ProtoAppConfig, InterfaceStatus, Rule, Zone, ZoneInterface, ZonePair};
use ngfw::proto::services::firewall_config_snapshot_service_client::FirewallConfigSnapshotServiceClient;
use ngfw::proto::services::firewall_query_service_client::FirewallQueryServiceClient;
use ngfw::proto::services::{
    ActiveConfigSnapshot, ConfigBundle, FactoryResetRequest,
    GetLiveZoneInterfacesRequest, GetPinningBypassRequest,
    GetPinningStatsRequest, GetPoliciesRequest, GetZoneInterfaceRequest,
    GetZoneInterfacesRequest, GetZonePairsRequest, GetZonesRequest, PushActiveConfigSnapshotRequest,
};
use ngfw::query_server::{QueryHandler, QueryServer};
use ngfw::tls::pinning_detector::PinningConfig;
use ngfw::tls::{DecryptionMirror, DecryptionMirrorConfig, EchTlsPolicy, ServerKeyStore, TlsDecisionEngine, TlsRedirectManager};
use ngfw::tls::redirect_manager::TlsRedirectCommandRunner;
use ngfw::interfaces::{InterfaceController, InterfaceControllerError, InterfaceMonitor, OperState, SystemInterface};
use ngfw::zones::provider::ZoneInterfaceProvider;
use ngfw::zones::provider::ZonePairProvider;
use ngfw::zones::provider::ZoneProvider;
use serial_test::serial;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct SharedServer {
    socket: String,
    config_provider: Arc<AppConfigProvider>,
    tls_redirect_runner: Arc<RecordingTlsRedirectRunner>,
}

#[derive(Default)]
struct RecordingTlsRedirectRunner {
    fail_apply: AtomicBool,
    scripts: StdMutex<Vec<String>>,
}

impl RecordingTlsRedirectRunner {
    fn clear(&self) {
        self.scripts.lock().unwrap().clear();
    }

    fn set_fail_apply(&self, value: bool) {
        self.fail_apply.store(value, Ordering::SeqCst);
    }

    fn scripts(&self) -> Vec<String> {
        self.scripts.lock().unwrap().clone()
    }
}

impl TlsRedirectCommandRunner for RecordingTlsRedirectRunner {
    fn table_exists(&self, _table_name: &str) -> anyhow::Result<bool> {
        Ok(false)
    }

    fn delete_table(&self, _table_name: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn apply_script(&self, script: &str) -> anyhow::Result<()> {
        self.scripts.lock().unwrap().push(script.to_string());
        if self.fail_apply.load(Ordering::SeqCst) {
            anyhow::bail!("injected tls redirect apply failure");
        }
        Ok(())
    }
}

#[derive(Default)]
struct NoopInterfaceController;

#[tonic::async_trait]
impl InterfaceController for NoopInterfaceController {
    async fn set_interface_state(&self, _name: &str, _up: bool) -> Result<(), InterfaceControllerError> {
        Ok(())
    }

    async fn set_interface_properties<'a>(
        &'a self,
        name: &'a str,
        new_name: Option<&'a str>,
        _address: Option<&'a str>,
    ) -> Result<String, InterfaceControllerError> {
        Ok(new_name.unwrap_or(name).to_string())
    }

    async fn create_vlan_subinterface<'a>(
        &'a self,
        _parent_name: &'a str,
        _vlan_id: ngfw::zones::VlanId,
        _subinterface_name: &'a str,
        _addresses: &'a [String],
    ) -> Result<(), InterfaceControllerError> {
        Ok(())
    }

    async fn delete_vlan_subinterface<'a>(
        &'a self,
        _subinterface_name: &'a str,
    ) -> Result<(), InterfaceControllerError> {
        Ok(())
    }
}

#[derive(Clone)]
struct StaticInterfaceMonitor {
    interfaces: HashMap<String, SystemInterface>,
}

impl StaticInterfaceMonitor {
    fn new() -> Self {
        Self {
            interfaces: HashMap::from([
                (
                    "eth-live-up".to_string(),
                    SystemInterface {
                        index: 10.into(),
                        name: "eth-live-up".to_string(),
                        oper_state: OperState::Up,
                        addresses: vec![
                            "192.168.50.10/24".parse::<IpNet>().expect("valid CIDR"),
                            "fe80::10/64".parse::<IpNet>().expect("valid CIDR"),
                        ],
                        vlan_id: None,
                    },
                ),
                (
                    "eth-live-up.100".to_string(),
                    SystemInterface {
                        index: 100.into(),
                        name: "eth-live-up.100".to_string(),
                        oper_state: OperState::Up,
                        addresses: vec![
                            "192.168.100.10/24".parse::<IpNet>().expect("valid CIDR"),
                        ],
                        vlan_id: Some(100),
                    },
                ),
                (
                    "eth-live-down".to_string(),
                    SystemInterface {
                        index: 11.into(),
                        name: "eth-live-down".to_string(),
                        oper_state: OperState::Down,
                        addresses: vec!["10.20.30.40/24".parse::<IpNet>().expect("valid CIDR")],
                        vlan_id: None,
                    },
                ),
                (
                    "eth-live-unknown".to_string(),
                    SystemInterface {
                        index: 12.into(),
                        name: "eth-live-unknown".to_string(),
                        oper_state: OperState::Unknown,
                        addresses: vec!["172.16.0.10/16".parse::<IpNet>().expect("valid CIDR")],
                        vlan_id: None,
                    },
                ),
            ]),
        }
    }
}

impl InterfaceMonitor for StaticInterfaceMonitor {
    fn get(&self, name: &str) -> Option<SystemInterface> {
        self.interfaces.get(name).cloned()
    }

    fn get_by_index(&self, index: ngfw::interfaces::SystemInterfaceId) -> Option<SystemInterface> {
        self.interfaces.values().find(|i| i.index == index).cloned()
    }

    fn snapshot(&self) -> HashMap<String, SystemInterface> {
        self.interfaces.clone()
    }
}

static SHARED_SERVER: OnceLock<SharedServer> = OnceLock::new();

fn shared_server() -> &'static SharedServer {
    SHARED_SERVER.get_or_init(|| {
        unsafe { env::set_var("POLICIES_DIRECTORY", "/tmp") };

        // Channel lets us wait until the server is actually listening
        // before returning, without an arbitrary sleep.
        let (tx, rx) = std::sync::mpsc::channel::<(String, Arc<AppConfigProvider>)>();
        let tls_redirect_runner = Arc::new(RecordingTlsRedirectRunner::default());
        let runner_for_server = Arc::clone(&tls_redirect_runner);
        let socket = "/tmp/test-query-shared.sock".to_string();
        let _ = std::fs::remove_file(&socket);
        let socket_for_server = socket.clone();

        std::thread::spawn(move || {
            // This runtime lives for the lifetime of the process —
            // it is never dropped, so the server task is never killed.
            let rt = tokio::runtime::Runtime::new().expect("failed to build server runtime");
            rt.block_on(async move {
                let config_provider = Arc::new(
                    AppConfigProvider::from_env()
                        .await
                        .expect("failed to load config"),
                );
                let config = config_provider.get_config();
                let policy = DiskPolicyProvider::from_loaded(&config)
                    .await
                    .expect("failed to load policy provider");
                let zones = ZoneProvider::from_disk(&config).await;
                let zone_pairs = ZonePairProvider::from_disk(&config).await;
                let interface_monitor = Arc::new(StaticInterfaceMonitor::new());
                let zone_interfaces = ZoneInterfaceProvider::collect(&config, &*interface_monitor).await;
                let dns_inspection_store =
                    Arc::new(DnsInspectionConfigProvider::from_disk(config.data_dir.clone()).await);
                let dns_initial_config = dns_inspection_store.get_config().clone();
                let dns_inspection = DnsInspection::new((*dns_initial_config).clone())
                    .expect("failed to init dns inspection");
                let ips_store =
                    Arc::new(IpsConfigProvider::from_disk(config.data_dir.clone()).await);
                let ips_initial_config = ips_store.get_config().clone();
                let ips = Ips::new((*ips_initial_config).clone()).expect("failed to init ips");
                let nat_store =
                    Arc::new(NatConfigProvider::from_disk(config.data_dir.clone()).await);
                let server_key_store = Arc::new(ServerKeyStore::new(&config.pki_dir));
                let decision_engine = Arc::new(TlsDecisionEngine::new(
                    &config.ssl_bypass_domains,
                    Arc::clone(&server_key_store),
                    EchTlsPolicy::default(),
                    PinningConfig::default(),
                ));
                let interface_controller = Arc::new(NoopInterfaceController);

                let policy_engine = Arc::new(
                    ngfw::policy::engine::PolicyEngine::from_policies(
                        &policy.get_policies(),
                        &zone_pairs.get_zone_pairs(),
                    )
                    .unwrap(),
                );

                let vlan_reconciler = Arc::new(ngfw::interfaces::VlanReconciler::new(Arc::clone(&interface_controller)));
                let (interface_sniffer, _rx) = ngfw::data_plane::interface_sniffer::InterfaceSniffer::with_sniffing(100);
                let interface_sniffer = Arc::new(interface_sniffer);

                let proto_reg = {
                    use ngfw::conntrack::proto::{tcp::TcpHandler, udp::UdpHandler, icmp::IcmpHandler, ProtoRegistry};
                    use ngfw::conntrack::observer::ObserverRegistry;

                    let observers = Arc::new(ObserverRegistry::default());
                    let mut reg = ProtoRegistry::new();

                    reg.register(Arc::new(TcpHandler::new(Arc::clone(&observers))));
                    reg.register(Arc::new(UdpHandler::new(Arc::clone(&observers))));
                    reg.register(Arc::new(IcmpHandler::v4()));
                    reg.register(Arc::new(IcmpHandler::v6()));

                    reg
                };
                let conntrack_for_test = Arc::new(ngfw::conntrack::table::Conntrack::new(
                    Arc::new(proto_reg),
                    ngfw::conntrack::config::ConntrackConfig::default(),
                ));

                let handler = QueryHandler {
                    tcp_tracker: TcpSessionTracker::new(),
                    nat_engine: NatEngine::new(None, HashMap::new()),
                    nat_store,
                    conntrack: conntrack_for_test,
                    policy_store: Arc::new(policy),
                    policy_engine,
                    zone_store: Arc::new(zones),
                    zone_pair_store: Arc::new(zone_pairs),
                    zone_interface_store: Arc::new(zone_interfaces),
                    config_provider: Arc::clone(&config_provider),
                    dns_inspection_store,
                    dns_inspection,
                    ips_store,
                    ips,
                    decision_engine: Arc::clone(&decision_engine),
                    decryption_mirror: Arc::new(DecryptionMirror::start(DecryptionMirrorConfig::default(), CancellationToken::new())),
                    tls_redirect_manager: Arc::new(TlsRedirectManager::with_runner(runner_for_server.clone())),
                    server_key_store,
                    pinning_detector: decision_engine.pinning_detector_arc(),
                    interface_monitor,
                    interface_controller,
                    vlan_reconciler,
                    interface_sniffer,
                    metrics_collector: Arc::new(ngfw::metrics::MetricsCollector::new()),
                    reset_lock: Arc::new(Mutex::new(())),
                };

                let socket = socket_for_server;
                let shutdown = CancellationToken::new();
                let identity_sessions = IdentitySessionStore::new_shared();
                let server =
                    QueryServer::new(handler, identity_sessions, &socket, shutdown.clone());

                // Signal readiness before blocking on serve()
                tx.send((socket, Arc::clone(&config_provider))).expect("receiver dropped");

                server.serve().await;
            });
        });

        let (socket, config_provider) = rx.recv().expect("server thread died before signalling");
        SharedServer { socket, config_provider, tls_redirect_runner }
    })
}

async fn connect(socket: &str) -> FirewallQueryServiceClient<tonic::transport::Channel> {
    wait_for_socket(socket).await;
    let socket = socket.to_owned();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = socket.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .unwrap();
    FirewallQueryServiceClient::new(channel)
}

async fn connect_snapshot(
    socket: &str,
) -> FirewallConfigSnapshotServiceClient<tonic::transport::Channel> {
    wait_for_socket(socket).await;
    let socket = socket.to_owned();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = socket.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .unwrap();
    FirewallConfigSnapshotServiceClient::new(channel)
}

async fn wait_for_socket(socket: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !Path::new(socket).exists() {
        assert!(Instant::now() < deadline, "query socket did not appear: {socket}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

struct ValidBundle {
    bundle: ConfigBundle,
    rule: Rule,
    src_zone: Zone,
    dst_zone: Zone,
    zone_pair: ZonePair,
}

fn create_valid_bundle(rule_name: &str, content: &str) -> ValidBundle {
    let default_zone = Zone {
        id: Uuid::nil().to_string(),
        name: "default".to_string(),
    };
    let src_zone = Zone {
        id: Uuid::now_v7().to_string(),
        name: format!("{rule_name}_src"),
    };
    let dst_zone = Zone {
        id: Uuid::now_v7().to_string(),
        name: format!("{rule_name}_dst"),
    };
    let zone_pair = ZonePair {
        id: Uuid::now_v7().to_string(),
        src_zone_id: src_zone.id.clone(),
        dst_zone_id: dst_zone.id.clone(),
        default_policy: Default::default(),
    };
    let rule = Rule {
        id: Uuid::now_v7().to_string(),
        name: rule_name.to_string(),
        zone_pair_id: zone_pair.id.clone(),
        priority: 0,
        content: content.to_string(),
        smtp_matchers: None,
    };

    let bundle = ConfigBundle {
        rules: vec![rule.clone()],
        zones: vec![default_zone.clone(), src_zone.clone(), dst_zone.clone()],
        zone_pairs: vec![zone_pair.clone()],
        ..Default::default()
    };

    ValidBundle {
        bundle,
        rule,
        src_zone,
        dst_zone,
        zone_pair,
    }
}

fn create_valid_bundle_with_zone_interfaces(
    rule_name: &str,
    content: &str,
    zone_interfaces: Vec<ZoneInterface>,
) -> ValidBundle {
    let mut valid = create_valid_bundle(rule_name, content);
    valid.bundle.zone_interfaces = zone_interfaces;
    valid
}

fn create_snapshot_request(
    bundle: ConfigBundle,
) -> (PushActiveConfigSnapshotRequest, String, String) {
    let correlation_id = Uuid::now_v7().to_string();
    let snapshot_id = Uuid::now_v7().to_string();

    (
        PushActiveConfigSnapshotRequest {
            correlation_id: correlation_id.clone(),
            snapshot: Some(ActiveConfigSnapshot {
                id: snapshot_id.clone(),
                version_number: 1,
                snapshot_type: "manual_import".into(),
                checksum: "test-checksum".into(),
                is_active: true,
                changes_summary: "test snapshot".into(),
                created_at: None,
                created_by: "test_query_server".into(),
                bundle: Some(bundle),
            }),
            reason: "apply".into(),
        },
        correlation_id,
        snapshot_id,
    )
}

fn app_config_proto(ssl_inspection_enabled: bool) -> ProtoAppConfig {
    ProtoAppConfig {
        pcap_timeout_ms: 100,
        tun_device_name: "tun0".to_string(),
        tun_address: "10.255.0.1".to_string(),
        tun_netmask: "255.255.255.0".to_string(),
        data_dir: "/tmp".to_string(),
        event_socket_path: "/tmp/test-events.sock".to_string(),
        query_socket_path: "/tmp/test-query-shared.sock".to_string(),
        pki_dir: "/tmp".to_string(),
        ssl_inspection_enabled,
        mitm_listen_addr: "127.0.0.1:8443".to_string(),
        control_plane_socket_path: "/tmp/test-control-plane.sock".to_string(),
        ssl_bypass_domains: vec![],
        tls_inspection_ports: vec![443],
        block_tls_on_undeclared_ports: false,
        server_cert_socket_path: "/tmp/test-server-cert.sock".to_string(),
    }
}

#[tokio::test]
#[serial(snapshot_bundle, nat_config)]
async fn push_active_config_snapshot_happy_path() {
    let mut client = connect_snapshot(&shared_server().socket).await;
    let valid = create_valid_bundle(
        "snapshot_happy",
        "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } =v6: verdict drop }",
    );
    let (request, correlation_id, snapshot_id) = create_snapshot_request(valid.bundle);

    let response = client
        .push_active_config_snapshot(request)
        .await
        .unwrap()
        .into_inner();

    assert!(response.accepted);
    assert_eq!(response.correlation_id, correlation_id);
    assert_eq!(response.applied_snapshot_id, snapshot_id);
}

#[tokio::test]
#[serial(snapshot_bundle, nat_config)]
async fn push_active_config_snapshot_reconciles_tls_redirect_for_sniffed_interfaces() {
    let server = shared_server();
    let mut client = connect_snapshot(&server.socket).await;
    let mut valid = create_valid_bundle(
        "snapshot_tls_redirect",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    valid.bundle.zone_interfaces = vec![ZoneInterface {
        id: Uuid::now_v7().to_string(),
        zone_id: valid.src_zone.id.clone(),
        status: InterfaceStatus::Unspecified as i32,
        addresses: vec![],
        kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
            ngfw::proto::config::PhysicalInterface {
                interface_name: "eth-live-up".to_string(),
            },
        )),
        sniffed: true,
    }];
    valid.bundle.app_config = Some(app_config_proto(true));

    server.tls_redirect_runner.clear();
    let (request, _, _) = create_snapshot_request(valid.bundle);
    let response = client
        .push_active_config_snapshot(request)
        .await
        .unwrap()
        .into_inner();

    assert!(response.accepted, "snapshot rejected: {}", response.message);
    let scripts = server.tls_redirect_runner.scripts();
    assert_eq!(scripts.len(), 1);
    assert!(scripts[0].contains("table inet raptorgate_tls"));
    assert!(scripts[0].contains("iifname { \"eth-live-up\" } tcp dport { 443 } redirect to :8443"));

    let mut reset = create_valid_bundle(
        "snapshot_tls_redirect_reset",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    reset.bundle.app_config = Some(app_config_proto(false));
    let (reset_request, _, _) = create_snapshot_request(reset.bundle);
    let reset_response = client
        .push_active_config_snapshot(reset_request)
        .await
        .unwrap()
        .into_inner();
    assert!(reset_response.accepted, "reset snapshot rejected: {}", reset_response.message);
}

#[tokio::test]
#[serial(snapshot_bundle, nat_config)]
async fn push_active_config_snapshot_rejects_tls_redirect_without_swapping_zone_interfaces() {
    let server = shared_server();
    let mut snapshot_client = connect_snapshot(&server.socket).await;
    let mut query_client = connect(&server.socket).await;
    let mut initial = create_valid_bundle(
        "snapshot_tls_empty_initial",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    let initial_zone_interface_id = Uuid::now_v7().to_string();
    initial.bundle.zone_interfaces = vec![ZoneInterface {
        id: initial_zone_interface_id.clone(),
        zone_id: initial.src_zone.id.clone(),
        status: InterfaceStatus::Unspecified as i32,
        addresses: vec![],
        kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
            ngfw::proto::config::PhysicalInterface {
                interface_name: "eth-live-up".to_string(),
            },
        )),
        sniffed: true,
    }];
    initial.bundle.app_config = Some(app_config_proto(false));

    server.tls_redirect_runner.clear();
    let (initial_request, _, _) = create_snapshot_request(initial.bundle);
    let initial_response = snapshot_client
        .push_active_config_snapshot(initial_request)
        .await
        .unwrap()
        .into_inner();
    assert!(initial_response.accepted, "initial snapshot rejected: {}", initial_response.message);

    let mut invalid = create_valid_bundle(
        "snapshot_tls_empty_invalid",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    let invalid_zone_interface_id = Uuid::now_v7().to_string();
    invalid.bundle.zone_interfaces = vec![ZoneInterface {
        id: invalid_zone_interface_id.clone(),
        zone_id: invalid.src_zone.id.clone(),
        status: InterfaceStatus::Unspecified as i32,
        addresses: vec![],
        kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
            ngfw::proto::config::PhysicalInterface {
                interface_name: "eth-live-down".to_string(),
            },
        )),
        sniffed: false,
    }];
    invalid.bundle.app_config = Some(app_config_proto(true));

    let (invalid_request, _, _) = create_snapshot_request(invalid.bundle);
    let invalid_response = snapshot_client
        .push_active_config_snapshot(invalid_request)
        .await
        .unwrap()
        .into_inner();
    assert!(!invalid_response.accepted);
    assert!(invalid_response.message.contains("tls redirect reconcile failed"));
    assert!(!server.config_provider.get_config().ssl_inspection_enabled);

    let zone_interfaces = query_client
        .get_zone_interfaces(GetZoneInterfacesRequest {})
        .await
        .unwrap()
        .into_inner()
        .zone_interfaces;
    let kept = zone_interfaces
        .iter()
        .find(|zi| zi.id == initial_zone_interface_id)
        .expect("previous zone interface should remain active");
    assert!(kept.sniffed);
    assert!(matches!(
        kept.kind.as_ref(),
        Some(ngfw::proto::config::zone_interface::Kind::Physical(p)) if p.interface_name == "eth-live-up"
    ));
    assert!(!zone_interfaces.iter().any(|zi| zi.id == invalid_zone_interface_id));

    let mut reset = create_valid_bundle(
        "snapshot_tls_empty_reset",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    reset.bundle.app_config = Some(app_config_proto(false));
    let (reset_request, _, _) = create_snapshot_request(reset.bundle);
    let reset_response = snapshot_client
        .push_active_config_snapshot(reset_request)
        .await
        .unwrap()
        .into_inner();
    assert!(reset_response.accepted, "reset snapshot rejected: {}", reset_response.message);
}

#[tokio::test]
#[serial(snapshot_bundle, nat_config)]
async fn push_active_config_snapshot_restores_previous_tls_redirect_when_empty_snapshot_rejected() {
    let server = shared_server();
    let mut snapshot_client = connect_snapshot(&server.socket).await;
    let mut initial = create_valid_bundle(
        "snapshot_tls_empty_restore_initial",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    initial.bundle.zone_interfaces = vec![ZoneInterface {
        id: Uuid::now_v7().to_string(),
        zone_id: initial.src_zone.id.clone(),
        status: InterfaceStatus::Unspecified as i32,
        addresses: vec![],
        kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
            ngfw::proto::config::PhysicalInterface {
                interface_name: "eth-live-up".to_string(),
            },
        )),
        sniffed: true,
    }];
    initial.bundle.app_config = Some(app_config_proto(true));

    server.tls_redirect_runner.clear();
    let (initial_request, _, _) = create_snapshot_request(initial.bundle);
    let initial_response = snapshot_client
        .push_active_config_snapshot(initial_request)
        .await
        .unwrap()
        .into_inner();
    assert!(initial_response.accepted, "initial snapshot rejected: {}", initial_response.message);
    server.tls_redirect_runner.clear();

    let mut invalid = create_valid_bundle(
        "snapshot_tls_empty_restore_invalid",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    invalid.bundle.zone_interfaces = vec![ZoneInterface {
        id: Uuid::now_v7().to_string(),
        zone_id: invalid.src_zone.id.clone(),
        status: InterfaceStatus::Unspecified as i32,
        addresses: vec![],
        kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
            ngfw::proto::config::PhysicalInterface {
                interface_name: "eth-live-down".to_string(),
            },
        )),
        sniffed: false,
    }];
    invalid.bundle.app_config = Some(app_config_proto(true));

    let (invalid_request, _, _) = create_snapshot_request(invalid.bundle);
    let invalid_response = snapshot_client
        .push_active_config_snapshot(invalid_request)
        .await
        .unwrap()
        .into_inner();
    assert!(!invalid_response.accepted);
    assert!(invalid_response.message.contains("tls redirect reconcile failed"));

    let scripts = server.tls_redirect_runner.scripts();
    assert_eq!(scripts.len(), 1);
    assert!(scripts[0].contains("iifname { \"eth-live-up\" } tcp dport { 443 } redirect to :8443"));

    let mut reset = create_valid_bundle(
        "snapshot_tls_empty_restore_reset",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    reset.bundle.app_config = Some(app_config_proto(false));
    let (reset_request, _, _) = create_snapshot_request(reset.bundle);
    let reset_response = snapshot_client
        .push_active_config_snapshot(reset_request)
        .await
        .unwrap()
        .into_inner();
    assert!(reset_response.accepted, "reset snapshot rejected: {}", reset_response.message);
}

#[tokio::test]
#[serial(snapshot_bundle, nat_config)]
async fn push_active_config_snapshot_rolls_back_zone_interfaces_when_tls_redirect_apply_fails() {
    let server = shared_server();
    let mut snapshot_client = connect_snapshot(&server.socket).await;
    let mut query_client = connect(&server.socket).await;
    let mut initial = create_valid_bundle(
        "snapshot_tls_apply_failure_initial",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    let initial_zone_interface_id = Uuid::now_v7().to_string();
    initial.bundle.zone_interfaces = vec![ZoneInterface {
        id: initial_zone_interface_id.clone(),
        zone_id: initial.src_zone.id.clone(),
        status: InterfaceStatus::Unspecified as i32,
        addresses: vec![],
        kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
            ngfw::proto::config::PhysicalInterface {
                interface_name: "eth-live-up".to_string(),
            },
        )),
        sniffed: true,
    }];
    initial.bundle.app_config = Some(app_config_proto(false));

    server.tls_redirect_runner.clear();
    server.tls_redirect_runner.set_fail_apply(false);
    let (initial_request, _, _) = create_snapshot_request(initial.bundle);
    let initial_response = snapshot_client
        .push_active_config_snapshot(initial_request)
        .await
        .unwrap()
        .into_inner();
    assert!(initial_response.accepted, "initial snapshot rejected: {}", initial_response.message);

    let mut invalid = create_valid_bundle(
        "snapshot_tls_apply_failure_invalid",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    let invalid_zone_interface_id = Uuid::now_v7().to_string();
    invalid.bundle.zone_interfaces = vec![ZoneInterface {
        id: invalid_zone_interface_id.clone(),
        zone_id: invalid.src_zone.id.clone(),
        status: InterfaceStatus::Unspecified as i32,
        addresses: vec![],
        kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
            ngfw::proto::config::PhysicalInterface {
                interface_name: "eth-live-up.100".to_string(),
            },
        )),
        sniffed: true,
    }];
    invalid.bundle.app_config = Some(app_config_proto(true));

    server.tls_redirect_runner.set_fail_apply(true);
    let (invalid_request, _, _) = create_snapshot_request(invalid.bundle);
    let invalid_response = snapshot_client
        .push_active_config_snapshot(invalid_request)
        .await
        .unwrap()
        .into_inner();
    server.tls_redirect_runner.set_fail_apply(false);
    assert!(!invalid_response.accepted);
    assert!(invalid_response.message.contains("tls redirect reconcile failed"));
    assert!(!server.config_provider.get_config().ssl_inspection_enabled);

    let zone_interfaces = query_client
        .get_zone_interfaces(GetZoneInterfacesRequest {})
        .await
        .unwrap()
        .into_inner()
        .zone_interfaces;
    let kept = zone_interfaces
        .iter()
        .find(|zi| zi.id == initial_zone_interface_id)
        .expect("previous zone interface should remain active");
    assert!(kept.sniffed);
    assert!(matches!(
        kept.kind.as_ref(),
        Some(ngfw::proto::config::zone_interface::Kind::Physical(p)) if p.interface_name == "eth-live-up"
    ));
    assert!(!zone_interfaces.iter().any(|zi| zi.id == invalid_zone_interface_id));

    let mut reset = create_valid_bundle(
        "snapshot_tls_apply_failure_reset",
        "match ip_ver { =v4: verdict allow =v6: verdict drop }",
    );
    reset.bundle.app_config = Some(app_config_proto(false));
    let (reset_request, _, _) = create_snapshot_request(reset.bundle);
    let reset_response = snapshot_client
        .push_active_config_snapshot(reset_request)
        .await
        .unwrap()
        .into_inner();
    assert!(reset_response.accepted, "reset snapshot rejected: {}", reset_response.message);
}

#[tokio::test]
#[serial(snapshot_bundle)]
async fn push_active_config_snapshot_integrity_error() {
    let mut client = connect_snapshot(&shared_server().socket).await;
    let valid = create_valid_bundle(
        "snapshot_integrity_error",
        "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } =v6: verdict drop }",
    );

    let mut broken_rule = valid.rule.clone();
    broken_rule.zone_pair_id = Uuid::now_v7().to_string();

    let broken_bundle = ConfigBundle {
        rules: vec![broken_rule],
        zones: vec![valid.src_zone, valid.dst_zone],
        zone_pairs: vec![valid.zone_pair],
        ..Default::default()
    };
    let (request, _, _) = create_snapshot_request(broken_bundle);

    let response = client
        .push_active_config_snapshot(request)
        .await;

    let inner = response.unwrap().into_inner();
    assert!(!inner.accepted);
    assert!(!inner.message.is_empty());
    let lowered = inner.message.to_lowercase();
    assert!(lowered.contains("zone") || lowered.contains("pair"));
    // TODO: Return a transport error for integrity failures instead of accepted=false payloads.
}

#[tokio::test]
#[serial(snapshot_bundle)]
async fn push_active_config_snapshot_raptorlang_error() {
    let mut client = connect_snapshot(&shared_server().socket).await;
    let invalid = create_valid_bundle("snapshot_raptorlang_error", "this is not valid raptorlang");
    let (request, _, _) = create_snapshot_request(invalid.bundle);

    let response = client.push_active_config_snapshot(request).await;

    assert!(response.is_err());
}

#[tokio::test]
#[serial(snapshot_bundle)]
async fn push_active_config_snapshot_invalid_smtp_regex_returns_invalid_argument() {
    let mut client = connect_snapshot(&shared_server().socket).await;
    let mut valid = create_valid_bundle("snapshot_invalid_smtp", "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } =v6: verdict drop }");

    valid.rule.smtp_matchers = Some(ngfw::proto::config::SmtpMatchers {
        sender: vec![ngfw::proto::config::SmtpMatch {
            regex: "[invalid".to_string(),
            on_match: ngfw::proto::config::SmtpMatchAction::Allow as i32,
        }],
        recipient: vec![],
        message: vec![],
    });

    let broken_bundle = ConfigBundle {
        rules: vec![valid.rule],
        zones: vec![valid.src_zone, valid.dst_zone],
        zone_pairs: vec![valid.zone_pair],
        ..Default::default()
    };
    let (request, _, _) = create_snapshot_request(broken_bundle);

    let response = client.push_active_config_snapshot(request).await;

    assert!(response.is_err());
    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("smtp_sender"));
}

#[tokio::test]
#[serial(snapshot_bundle, nat_config)]
async fn fetch_policies_returns_ok() {
    let mut snapshot_client = connect_snapshot(&shared_server().socket).await;
    let mut query_client = connect(&shared_server().socket).await;
    let valid = create_valid_bundle(
        "fetch_policies_returns_ok",
        "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } =v6: verdict drop }",
    );
    let expected_rule_name = valid.rule.name.clone();
    let (request, _, _) = create_snapshot_request(valid.bundle);

    let push_response = snapshot_client
        .push_active_config_snapshot(request)
        .await
        .unwrap()
        .into_inner();
    assert!(push_response.accepted);

    let resp = query_client.get_policies(GetPoliciesRequest {}).await.unwrap();
    let inner = resp.into_inner();

    assert!(
        inner.rules.iter().any(|r| r.name == expected_rule_name),
        "expected rule '{}' to be present, got: {:?}",
        expected_rule_name,
        inner.rules.iter().map(|r| &r.name).collect::<Vec<_>>()
    );
}

#[tokio::test]
#[serial(snapshot_bundle, nat_config, ips_config)]
async fn factory_reset_restores_safe_defaults() {
    let mut snapshot_client = connect_snapshot(&shared_server().socket).await;
    let mut query_client = connect(&shared_server().socket).await;
    let valid = create_valid_bundle(
        "factory_reset_rule",
        "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } =v6: verdict drop }",
    );
    let (request, _, _) = create_snapshot_request(valid.bundle);

    let push_response = snapshot_client
        .push_active_config_snapshot(request)
        .await
        .unwrap()
        .into_inner();
    assert!(push_response.accepted);

    let reset_response = snapshot_client
        .factory_reset(FactoryResetRequest {
            correlation_id: Uuid::now_v7().to_string(),
            reason: "test".into(),
            clear_pki: Some(false),
            clear_server_keys: Some(true),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(reset_response.accepted);
    assert!(reset_response.safe_state_applied);

    let policies = query_client
        .get_policies(GetPoliciesRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(policies.rules.len(), 1);
    assert_eq!(policies.rules[0].name, "Default policy");
}

#[tokio::test]
#[serial(snapshot_bundle, nat_config)]
async fn fetch_zones_returns_ok() {
    let mut snapshot_client = connect_snapshot(&shared_server().socket).await;
    let mut query_client = connect(&shared_server().socket).await;
    let valid = create_valid_bundle(
        "fetch_zones_returns_ok",
        "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } =v6: verdict drop }",
    );
    let expected_zone_names = [valid.src_zone.name.clone(), valid.dst_zone.name.clone()];
    let (request, _, _) = create_snapshot_request(valid.bundle);

    let push_response = snapshot_client
        .push_active_config_snapshot(request)
        .await
        .unwrap()
        .into_inner();
    assert!(push_response.accepted);

    let resp = query_client
        .get_zones(GetZonesRequest {})
        .await
        .unwrap();
    let inner = resp.into_inner();

    for expected_zone_name in expected_zone_names {
        assert!(
            inner.zones.iter().any(|z| z.name == expected_zone_name),
            "expected zone '{}' to be present, got: {:?}",
            expected_zone_name,
            inner.zones.iter().map(|z| &z.name).collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
#[serial(snapshot_bundle, nat_config)]
async fn fetch_zone_interfaces_and_live_zone_interfaces_return_expected_contract() {
    let mut snapshot_client = connect_snapshot(&shared_server().socket).await;
    let mut query_client = connect(&shared_server().socket).await;
    let mut valid = create_valid_bundle_with_zone_interfaces(
        "fetch_zone_interfaces_returns_ok",
        "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } =v6: verdict drop }",
        vec![],
    );

    let eth_live_up_id = Uuid::now_v7().to_string();

    let zone_interfaces = vec![
        ZoneInterface {
            id: eth_live_up_id.clone(),
            zone_id: valid.src_zone.id.clone(),
            status: InterfaceStatus::Unspecified as i32,
            addresses: vec![],
            kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
                ngfw::proto::config::PhysicalInterface {
                    interface_name: "eth-live-up".to_string(),
                },
            )),
            sniffed: false,
        },
        ZoneInterface {
            id: Uuid::now_v7().to_string(),
            zone_id: valid.src_zone.id.clone(),
            status: InterfaceStatus::Unspecified as i32,
            addresses: vec![],
            kind: Some(ngfw::proto::config::zone_interface::Kind::Vlan(
                ngfw::proto::config::VlanSubinterface {
                    parent_interface_id: eth_live_up_id.clone(),
                    vlan_id: 100,
                },
            )),
            sniffed: false,
        },
        ZoneInterface {
            id: Uuid::now_v7().to_string(),
            zone_id: valid.dst_zone.id.clone(),
            status: InterfaceStatus::Unspecified as i32,
            addresses: vec![],
            kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
                ngfw::proto::config::PhysicalInterface {
                    interface_name: "eth-live-unknown".to_string(),
                },
            )),
            sniffed: false,
        },
        ZoneInterface {
            id: Uuid::now_v7().to_string(),
            zone_id: valid.dst_zone.id.clone(),
            status: InterfaceStatus::Unspecified as i32,
            addresses: vec![],
            kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
                ngfw::proto::config::PhysicalInterface {
                    interface_name: "eth-live-down".to_string(),
                },
            )),
            sniffed: false,
        },
        ZoneInterface {
            id: Uuid::now_v7().to_string(),
            zone_id: valid.dst_zone.id.clone(),
            status: InterfaceStatus::Unspecified as i32,
            addresses: vec![],
            kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
                ngfw::proto::config::PhysicalInterface {
                    interface_name: "eth-live-missing".to_string(),
                },
            )),
            sniffed: false,
        },
    ];
    
    // Helper to extract interface name from proto ZoneInterface
    let eth_live_up_id_clone = eth_live_up_id.clone();
    let get_interface_name = move |zi: &ZoneInterface| -> Option<String> {
        zi.kind.as_ref().and_then(|k| match k {
            ngfw::proto::config::zone_interface::Kind::Physical(p) => Some(p.interface_name.clone()),
            ngfw::proto::config::zone_interface::Kind::Vlan(v) => {
                if v.parent_interface_id == eth_live_up_id_clone {
                    Some(format!("eth-live-up.{}", v.vlan_id))
                } else {
                    None
                }
            }
        })
    };
    
    let expected_by_name: HashMap<String, ZoneInterface> = zone_interfaces
        .iter()
        .filter_map(|zi| get_interface_name(zi).map(|name| (name, zi.clone())))
        .collect();
    
    let expected_zone_interface_id = zone_interfaces[0].id.clone();
    valid.bundle.zone_interfaces = zone_interfaces.clone();

    let (request, _, _) = create_snapshot_request(valid.bundle);
    let push_response = snapshot_client
        .push_active_config_snapshot(request)
        .await
        .unwrap()
        .into_inner();
    assert!(push_response.accepted, "snapshot rejected: {}", push_response.message);

    let raw_response = query_client
        .get_zone_interfaces(GetZoneInterfacesRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(raw_response.zone_interfaces.len(), zone_interfaces.len());

    for zone_interface in &raw_response.zone_interfaces {
        if let Some(name) = get_interface_name(zone_interface) {
            let expected = expected_by_name
                .get(&name)
                .expect("raw interface present in expected map");
            assert_eq!(zone_interface.id, expected.id);
            assert_eq!(zone_interface.zone_id, expected.zone_id);
            assert_eq!(zone_interface.status, InterfaceStatus::Unspecified as i32);
            assert!(zone_interface.addresses.is_empty());
        }
    }

    let single_response = query_client
        .get_zone_interface(GetZoneInterfaceRequest {
            id: expected_zone_interface_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let single = single_response
        .zone_interface
        .expect("zone interface should be returned");
    assert_eq!(single.id, expected_zone_interface_id);
    assert_eq!(get_interface_name(&single).unwrap(), "eth-live-up");
    assert_eq!(single.status, InterfaceStatus::Unspecified as i32);
    assert!(single.addresses.is_empty());

    let live_response = query_client
        .get_live_zone_interfaces(GetLiveZoneInterfacesRequest {})
        .await
        .unwrap()
        .into_inner();
    let live_by_name: HashMap<String, ZoneInterface> = live_response
        .zone_interfaces
        .into_iter()
        .filter_map(|zone_interface| {
            get_interface_name(&zone_interface).map(|name| (name, zone_interface))
        })
        .collect();

    assert_eq!(
        live_by_name
            .get("eth-live-up")
            .expect("live up interface present")
            .status,
        InterfaceStatus::Active as i32
    );
    assert_eq!(
        live_by_name
            .get("eth-live-up")
            .expect("live up interface present")
            .addresses,
        vec!["192.168.50.10/24".to_string(), "fe80::10/64".to_string()]
    );

    assert_eq!(
        live_by_name
            .get("eth-live-up.100")
            .expect("live up vlan interface present")
            .status,
        InterfaceStatus::Active as i32
    );

    assert_eq!(
        live_by_name
            .get("eth-live-down")
            .expect("live down interface present")
            .status,
        InterfaceStatus::Inactive as i32
    );
    assert_eq!(
        live_by_name
            .get("eth-live-unknown")
            .expect("live unknown interface present")
            .status,
        InterfaceStatus::Unknown as i32
    );
    assert_eq!(
        live_by_name
            .get("eth-live-missing")
            .expect("missing interface present")
            .status,
        InterfaceStatus::Missing as i32
    );
    assert!(
        live_by_name
            .get("eth-live-missing")
            .expect("missing interface present")
            .addresses
            .is_empty()
    );
}

#[tokio::test]
#[serial(snapshot_bundle, nat_config)]
async fn fetch_zone_pairs_returns_ok() {
    let mut snapshot_client = connect_snapshot(&shared_server().socket).await;
    let mut query_client = connect(&shared_server().socket).await;
    let valid = create_valid_bundle(
        "fetch_zone_pairs_returns_ok",
        "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } =v6: verdict drop }",
    );
    let expected_zone_pair_id = valid.zone_pair.id.clone();
    let (request, _, _) = create_snapshot_request(valid.bundle);

    let push_response = snapshot_client
        .push_active_config_snapshot(request)
        .await
        .unwrap()
        .into_inner();
    assert!(push_response.accepted);

    let resp = query_client
        .get_zone_pairs(GetZonePairsRequest {})
        .await
        .unwrap();
    let inner = resp.into_inner();
    assert!(
        inner.zone_pairs.iter().any(|zp| zp.id == expected_zone_pair_id),
        "expected zone pair with id '{}' to be present, got: {:?}",
        expected_zone_pair_id,
        inner.zone_pairs.iter().map(|zp| &zp.id).collect::<Vec<_>>()
    );
}

#[tokio::test]
#[serial(pinning)]
async fn get_pinning_stats_returns_ok() {
    let mut client = connect(&shared_server().socket).await;
    let resp = client
        .get_pinning_stats(GetPinningStatsRequest {})
        .await
        .unwrap()
        .into_inner();
    // Shared server startuje ze swiezym detektorem — zerowe liczniki sa oczekiwane.
    assert_eq!(resp.active_bypasses, 0);
    assert_eq!(resp.tracked_failures, 0);
}

#[tokio::test]
#[serial(pinning)]
async fn get_pinning_bypass_invalid_ip_returns_error() {
    let mut client = connect(&shared_server().socket).await;
    let err = client
        .get_pinning_bypass(GetPinningBypassRequest {
            source_ip: "not-an-ip".into(),
            domain: "example.com".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
#[serial(pinning)]
async fn get_pinning_bypass_missing_returns_not_found() {
    let mut client = connect(&shared_server().socket).await;
    let resp = client
        .get_pinning_bypass(GetPinningBypassRequest {
            source_ip: "10.0.0.99".into(),
            domain: "definitely-not-pinned.example".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!resp.found);
    assert_eq!(resp.failure_count, 0);
    assert!(resp.reason.is_empty());
}

#[tokio::test]
#[serial(snapshot_bundle)]
async fn push_active_config_snapshot_rejects_missing_default_zone() {
    let mut client = connect_snapshot(&shared_server().socket).await;
    let mut valid = create_valid_bundle("snapshot_missing_default", "match ip_ver { =v4: verdict allow =v6: verdict drop }");
    valid.bundle.zones = valid.bundle.zones.into_iter().filter(|z| z.id != Uuid::nil().to_string()).collect();
    let (request, _, _) = create_snapshot_request(valid.bundle);

    let response = client
        .push_active_config_snapshot(request)
        .await
        .unwrap()
        .into_inner();

    assert!(!response.accepted);
    assert!(response.message.to_lowercase().contains("default"));
}
