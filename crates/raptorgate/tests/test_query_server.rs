use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::sync::OnceLock;

use ipnet::IpNet;
use ngfw::config::provider::AppConfigProvider;
use ngfw::data_plane::dns_inspection::dns_inspection::DnsInspection;
use ngfw::data_plane::dns_inspection::provider::DnsInspectionConfigProvider;
use ngfw::data_plane::ips::ips::Ips;
use ngfw::data_plane::ips::provider::IpsConfigProvider;
use ngfw::data_plane::nat::{NatConfigProvider, NatEngine};
use ngfw::data_plane::tcp_session_tracker::TcpSessionTracker;
use ngfw::policy::provider::DiskPolicyProvider;
use ngfw::proto::config::{InterfaceStatus, Rule, Zone, ZoneInterface, ZonePair};
use ngfw::proto::services::firewall_config_snapshot_service_client::FirewallConfigSnapshotServiceClient;
use ngfw::proto::services::firewall_query_service_client::FirewallQueryServiceClient;
use ngfw::proto::services::{
    ActiveConfigSnapshot, ConfigBundle, GetConfigRequest, GetIpsConfigRequest,
    GetLiveZoneInterfacesRequest, GetNatConfigRequest, GetPinningBypassRequest,
    GetPinningStatsRequest, GetPoliciesRequest, GetZoneInterfaceRequest,
    GetZoneInterfacesRequest, GetZonePairsRequest, GetZonesRequest,
    PushActiveConfigSnapshotRequest, SwapConfigRequest, SwapIpsConfigRequest,
    SwapNatConfigRequest,
};
use ngfw::query_server::{QueryHandler, QueryServer};
use ngfw::tls::pinning_detector::PinningConfig;
use ngfw::tls::{EchTlsPolicy, ServerKeyStore, TlsDecisionEngine};
use ngfw::interfaces::{InterfaceController, InterfaceMonitor, OperState, SystemInterface};
use ngfw::zones::provider::ZoneInterfaceProvider;
use ngfw::zones::provider::ZonePairProvider;
use ngfw::zones::provider::ZoneProvider;
use serial_test::serial;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct SharedServer {
    socket: String,
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
        let (tx, rx) = std::sync::mpsc::channel::<String>();

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
                let zone_interfaces = ZoneInterfaceProvider::from_disk(&config).await;
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
                let interface_monitor = Arc::new(StaticInterfaceMonitor::new());
                let interface_controller = Arc::new(
                    InterfaceController::new().expect("failed to init interface controller"),
                );

                let handler = QueryHandler {
                    tcp_tracker: TcpSessionTracker::new(),
                    nat_engine: Arc::new(Mutex::new(NatEngine::new(&None, HashMap::new()))),
                    nat_store,
                    policy_store: Arc::new(policy),
                    zone_store: Arc::new(zones),
                    zone_pair_store: Arc::new(zone_pairs),
                    zone_interface_store: Arc::new(zone_interfaces),
                    config_provider: Arc::clone(&config_provider),
                    dns_inspection_store,
                    dns_inspection,
                    ips_store,
                    ips,
                    decision_engine: Arc::clone(&decision_engine),
                    server_key_store,
                    pinning_detector: decision_engine.pinning_detector_arc(),
                    interface_monitor,
                    interface_controller,
                };

                let socket = "/tmp/test-query-shared.sock".to_string();
                let shutdown = CancellationToken::new();
                let server = QueryServer::new(handler, &socket, shutdown.clone());

                // Signal the socket path before we start blocking on serve()
                tx.send(socket).expect("receiver dropped");

                server.serve().await;
            });
        });

        let socket = rx.recv().expect("server thread died before signalling");
        SharedServer { socket }
    })
}

async fn connect(socket: &str) -> FirewallQueryServiceClient<tonic::transport::Channel> {
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

struct ValidBundle {
    bundle: ConfigBundle,
    rule: Rule,
    src_zone: Zone,
    dst_zone: Zone,
    zone_pair: ZonePair,
}

fn create_valid_bundle(rule_name: &str, content: &str) -> ValidBundle {
    let src_zone = Zone {
        id: Uuid::now_v7().to_string(),
        name: format!("{rule_name}_src"),
        interface_ids: vec![],
    };
    let dst_zone = Zone {
        id: Uuid::now_v7().to_string(),
        name: format!("{rule_name}_dst"),
        interface_ids: vec![],
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
    };

    let bundle = ConfigBundle {
        rules: vec![rule.clone()],
        zones: vec![src_zone.clone(), dst_zone.clone()],
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
    let mut interface_ids_by_zone: HashMap<String, Vec<String>> = zone_interfaces.iter().fold(
        HashMap::new(),
        |mut acc, zone_interface| {
            acc.entry(zone_interface.zone_id.clone())
                .or_default()
                .push(zone_interface.id.clone());
            acc
        },
    );
    valid.bundle.zones = valid
        .bundle
        .zones
        .into_iter()
        .map(|mut zone| {
            zone.interface_ids = interface_ids_by_zone
                .remove(&zone.id)
                .unwrap_or_default();
            zone
        })
        .collect();
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

    let zone_interfaces = vec![
        ZoneInterface {
            id: Uuid::now_v7().to_string(),
            zone_id: valid.src_zone.id.clone(),
            interface_name: "eth-live-up".to_string(),
            vlan_id: None,
            status: InterfaceStatus::Unspecified as i32,
            addresses: vec![],
        },
        ZoneInterface {
            id: Uuid::now_v7().to_string(),
            zone_id: valid.src_zone.id.clone(),
            interface_name: "eth-live-down".to_string(),
            vlan_id: Some(100),
            status: InterfaceStatus::Unspecified as i32,
            addresses: vec![],
        },
        ZoneInterface {
            id: Uuid::now_v7().to_string(),
            zone_id: valid.dst_zone.id.clone(),
            interface_name: "eth-live-unknown".to_string(),
            vlan_id: None,
            status: InterfaceStatus::Unspecified as i32,
            addresses: vec![],
        },
        ZoneInterface {
            id: Uuid::now_v7().to_string(),
            zone_id: valid.dst_zone.id.clone(),
            interface_name: "eth-live-missing".to_string(),
            vlan_id: None,
            status: InterfaceStatus::Unspecified as i32,
            addresses: vec![],
        },
    ];
    let expected_by_name: HashMap<String, ZoneInterface> = zone_interfaces
        .iter()
        .cloned()
        .map(|zone_interface| (zone_interface.interface_name.clone(), zone_interface))
        .collect();
    let expected_zone_interface_id = zone_interfaces[0].id.clone();
    valid.bundle.zone_interfaces = zone_interfaces;

    let (request, _, _) = create_snapshot_request(valid.bundle);
    let push_response = snapshot_client
        .push_active_config_snapshot(request)
        .await
        .unwrap()
        .into_inner();
    assert!(push_response.accepted);

    let raw_response = query_client
        .get_zone_interfaces(GetZoneInterfacesRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(raw_response.zone_interfaces.len(), expected_by_name.len());

    for zone_interface in &raw_response.zone_interfaces {
        let expected = expected_by_name
            .get(&zone_interface.interface_name)
            .expect("raw interface present in expected map");
        assert_eq!(zone_interface.id, expected.id);
        assert_eq!(zone_interface.zone_id, expected.zone_id);
        assert_eq!(zone_interface.vlan_id, expected.vlan_id);
        assert_eq!(zone_interface.status, InterfaceStatus::Unspecified as i32);
        assert!(zone_interface.addresses.is_empty());
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
    assert_eq!(single.interface_name, "eth-live-up");
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
        .map(|zone_interface| (zone_interface.interface_name.clone(), zone_interface))
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
#[serial(config)]
async fn swap_config_happy_path_returns_no_error() {
    let mut client = connect(&shared_server().socket).await;

    client
        .swap_config(SwapConfigRequest {
            config: Some(ngfw::proto::config::AppConfig {
                capture_interfaces: vec!["eth0".into(), "eth1".into()],
                pcap_timeout_ms: 3000,
                tun_device_name: "tun99".into(),
                tun_address: "10.254.254.1".into(),
                tun_netmask: "255.255.255.0".into(),
                data_dir: "/tmp".into(),
                event_socket_path: "./sockets/event.sock".into(),
                query_socket_path: "/tmp/test-query-shared.sock".into(),
                pki_dir: "/tmp/pki".into(),
                ssl_inspection_enabled: false,
                mitm_listen_addr: "127.0.0.1:8443".into(),
                control_plane_socket_path: "./sockets/control-plane.sock".into(),
                server_cert_socket_path: "./sockets/server-cert.sock".into(),
                ssl_bypass_domains: vec![],
                tls_inspection_ports: vec![443],
                block_tls_on_undeclared_ports: false,
            }),
        })
        .await
        .unwrap();
}

#[tokio::test]
#[serial(config)]
async fn get_config_returns_ok() {
    let mut client = connect(&shared_server().socket).await;

    let swapped = ngfw::proto::config::AppConfig {
        capture_interfaces: vec!["eth3".into()],
        pcap_timeout_ms: 7000,
        tun_device_name: "tun42".into(),
        tun_address: "192.168.1.1".into(),
        tun_netmask: "255.255.0.0".into(),
        data_dir: "/tmp".into(),
        event_socket_path: "./sockets/event.sock".into(),
        query_socket_path: "/tmp/test-query-shared.sock".into(),
        pki_dir: "/tmp/pki".into(),
        ssl_inspection_enabled: false,
        mitm_listen_addr: "127.0.0.1:8443".into(),
        control_plane_socket_path: "./sockets/control-plane.sock".into(),
        server_cert_socket_path: "./sockets/server-cert.sock".into(),
        ssl_bypass_domains: vec![],
        tls_inspection_ports: vec![443],
        block_tls_on_undeclared_ports: false,
    };

    client
        .swap_config(SwapConfigRequest {
            config: Some(swapped.clone()),
        })
        .await
        .unwrap();

    let resp = client.get_config(GetConfigRequest {}).await.unwrap();
    let inner = resp.into_inner();
    let config = inner.config.expect("get_config returned no config");

    assert_eq!(config.capture_interfaces, vec!["eth3"]);
    assert_eq!(config.pcap_timeout_ms, 7000);
    assert_eq!(config.tun_device_name, "tun42");
    assert_eq!(config.tun_address, "192.168.1.1");
    assert_eq!(config.tun_netmask, "255.255.0.0");
    assert_eq!(config.pki_dir, "/tmp/pki");
}

#[tokio::test]
#[serial(ips_config)]
async fn swap_and_get_ips_config_roundtrip() {
    let mut client = connect(&shared_server().socket).await;

    let swapped = ngfw::proto::config::IpsConfig {
        general: Some(ngfw::proto::config::IpsGeneralConfig { enabled: true }),
        detection: Some(ngfw::proto::config::IpsDetectionConfig {
            enabled: true,
            max_payload_bytes: 2048,
            max_matches_per_packet: 2,
        }),
        signatures: vec![ngfw::proto::config::IpsSignatureConfig {
            id: "sig-http-sqli".into(),
            name: "HTTP SQLi".into(),
            enabled: true,
            category: "sqli".into(),
            pattern: "(?i)union\\s+select".into(),
            match_type: ngfw::proto::config::IpsMatchType::Regex as i32,
            pattern_encoding: ngfw::proto::config::IpsPatternEncoding::Text as i32,
            case_insensitive: false,
            severity: ngfw::proto::common::Severity::High as i32,
            action: ngfw::proto::config::IpsAction::Block as i32,
            app_protocols: vec![ngfw::proto::config::IpsAppProtocol::Http as i32],
            src_ports: vec![],
            dst_ports: vec![80, 8080],
        }],
    };

    client
        .swap_ips_config(SwapIpsConfigRequest {
            config: Some(swapped.clone()),
        })
        .await
        .unwrap();

    let response = client
        .get_ips_config(GetIpsConfigRequest {})
        .await
        .unwrap()
        .into_inner();
    let config = response.config.expect("get_ips_config returned no config");

    assert!(config.general.expect("general").enabled);
    let detection = config.detection.expect("detection");
    assert_eq!(detection.max_payload_bytes, 2048);
    assert_eq!(detection.max_matches_per_packet, 2);
    assert_eq!(config.signatures.len(), 1);
    assert_eq!(config.signatures[0].id, "sig-http-sqli");
    assert_eq!(config.signatures[0].dst_ports, vec![80, 8080]);
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
#[serial(nat_config)]
async fn swap_and_get_nat_config_roundtrip() {
    let mut client = connect(&shared_server().socket).await;

    let swapped = ngfw::proto::config::NatRuleSet {
        items: vec![ngfw::proto::config::NatRule {
            id: "dnat-http".into(),
            r#type: ngfw::proto::common::NatRuleType::Dnat as i32,
            src_ip: String::new(),
            dst_ip: "203.0.113.10".into(),
            src_port: None,
            dst_port: Some(8080),
            translated_ip: "192.168.10.10".into(),
            translated_port: Some(80),
            priority: 10,
        }],
    };

    client
        .swap_nat_config(SwapNatConfigRequest {
            config: Some(swapped.clone()),
        })
        .await
        .unwrap();

    let response = client
        .get_nat_config(GetNatConfigRequest {})
        .await
        .unwrap()
        .into_inner();
    let config = response.config.expect("get_nat_config returned no config");

    assert_eq!(config.items.len(), 1);
    assert_eq!(config.items[0].id, "dnat-http");
    assert_eq!(
        config.items[0].r#type,
        ngfw::proto::common::NatRuleType::Dnat as i32
    );
    assert_eq!(config.items[0].dst_ip, "203.0.113.10");
    assert_eq!(config.items[0].dst_port, Some(8080));
    assert_eq!(config.items[0].translated_ip, "192.168.10.10");
    assert_eq!(config.items[0].translated_port, Some(80));
}

#[tokio::test]
#[serial(nat_config)]
async fn swap_nat_config_rejects_missing_config() {
    let mut client = connect(&shared_server().socket).await;

    let err = client
        .swap_nat_config(SwapNatConfigRequest { config: None })
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
#[serial(nat_config)]
async fn swap_nat_config_accepts_empty_rule_set() {
    let mut client = connect(&shared_server().socket).await;

    client
        .swap_nat_config(SwapNatConfigRequest {
            config: Some(ngfw::proto::config::NatRuleSet { items: vec![] }),
        })
        .await
        .unwrap();

    let response = client
        .get_nat_config(GetNatConfigRequest {})
        .await
        .unwrap()
        .into_inner();
    let config = response.config.expect("get_nat_config returned no config");

    assert!(config.items.is_empty());
}
