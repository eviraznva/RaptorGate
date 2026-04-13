use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::sync::OnceLock;

use ngfw::config_provider::AppConfigProvider;
use ngfw::data_plane::dns_inspection::dns_inspection::DnsInspection;
use ngfw::data_plane::dns_inspection::provider::DnsInspectionConfigProvider;
use ngfw::data_plane::ips::ips::Ips;
use ngfw::data_plane::ips::provider::IpsConfigProvider;
use ngfw::data_plane::nat::NatEngine;
use ngfw::data_plane::tcp_session_tracker::TcpSessionTracker;
use ngfw::policy::provider::DiskPolicyProvider;
use ngfw::proto::config::Rule;
use ngfw::proto::services::firewall_query_service_client::FirewallQueryServiceClient;
use ngfw::proto::services::{
    GetConfigRequest, GetIpsConfigRequest, GetPoliciesRequest, SwapConfigRequest,
    SwapIpsConfigRequest, SwapPoliciesRequest,
};
use ngfw::query_server::{QueryHandler, QueryServer};
use ngfw::zones::provider::ZonePairProvider;
use ngfw::zones::provider::ZoneProvider;
use serial_test::serial;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct SharedServer {
    socket: String,
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
                let dns_inspection_store =
                    Arc::new(DnsInspectionConfigProvider::from_disk(config.data_dir.clone()).await);
                let dns_initial_config = dns_inspection_store.get_config().clone();
                let dns_inspection = DnsInspection::new((*dns_initial_config).clone())
                    .expect("failed to init dns inspection");
                let ips_store =
                    Arc::new(IpsConfigProvider::from_disk(config.data_dir.clone()).await);
                let ips_initial_config = ips_store.get_config().clone();
                let ips = Ips::new((*ips_initial_config).clone()).expect("failed to init ips");

                let handler = QueryHandler {
                    tcp_tracker: TcpSessionTracker::new(),
                    nat_engine: Arc::new(Mutex::new(NatEngine::new(&None, HashMap::new()))),
                    policy_store: Arc::new(policy),
                    zone_store: Arc::new(zones),
                    zone_pair_store: Arc::new(zone_pairs),
                    config_provider: Arc::clone(&config_provider),
                    dns_inspection_store,
                    dns_inspection,
                    ips_store,
                    ips,
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

#[tokio::test]
#[serial(policies)] // has to be serial or else there's a race condition where after one test saves a new
// config, a second test may load the config saved by the first one.
async fn swap_policies_happy_path_returns_no_error() {
    let mut client = connect(&shared_server().socket).await;

    client
        .swap_policies(SwapPoliciesRequest {
            rules: vec![Rule {
                id: Uuid::now_v7().into(),
                name: "swap_happy".into(),
                zone_pair_id: Uuid::now_v7().into(),
                priority: 0,
                content: "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } =v6: verdict drop }".into(),
            }],
        })
        .await
        .unwrap();
}

#[tokio::test]
#[serial(policies)]
async fn swap_policies_error_path_returns_error_message() {
    let mut client = connect(&shared_server().socket).await;

    let resp = client
        .swap_policies(SwapPoliciesRequest {
            rules: vec![Rule {
                id: Uuid::now_v7().into(),
                name: "swap_unhappy".into(),
                zone_pair_id: Uuid::now_v7().into(),
                priority: 1,
                content: "this is not valid raptorlang".into(),
            }],
        })
        .await;

    assert!(resp.is_err());
}

#[tokio::test]
#[serial(policies)]
async fn fetch_policies_returns_ok() {
    let mut client = connect(&shared_server().socket).await;
    let rule = Rule {
        id: Uuid::now_v7().into(),
        name: "fetch_policies_returns_ok".into(), // unique per run
        zone_pair_id: Uuid::now_v7().into(),
        priority: 0,
        content: "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } =v6: verdict drop }".into(),
    };

    client
        .swap_policies(SwapPoliciesRequest {
            rules: vec![rule.clone()],
        })
        .await
        .unwrap();

    let resp = client.get_policies(GetPoliciesRequest {}).await.unwrap();
    let inner = resp.into_inner();

    // Don't assert on count or position — other tests race on the same server.
    // Assert only that *our* rule made it in.
    assert!(
        inner.rules.iter().any(|r| r.name == rule.name),
        "expected rule '{}' to be present, got: {:?}",
        rule.name,
        inner.rules.iter().map(|r| &r.name).collect::<Vec<_>>()
    );
}

#[tokio::test]
#[serial(zones)]
async fn swap_zones_happy_path_returns_no_error() {
    let mut client = connect(&shared_server().socket).await;
    client
        .swap_zones(ngfw::proto::services::SwapZonesRequest {
            zones: vec![ngfw::proto::config::Zone {
                id: Uuid::now_v7().into(),
                name: "swap_zone_happy".into(),
                interface_ids: vec![],
            }],
        })
        .await
        .unwrap();
}

#[tokio::test]
#[serial(zones)]
async fn fetch_zones_returns_ok() {
    let mut client = connect(&shared_server().socket).await;
    let zone = ngfw::proto::config::Zone {
        id: Uuid::now_v7().into(),
        name: "fetch_zones_ok".into(),
        interface_ids: vec![],
    };
    client
        .swap_zones(ngfw::proto::services::SwapZonesRequest {
            zones: vec![zone.clone()],
        })
        .await
        .unwrap();
    let resp = client
        .get_zones(ngfw::proto::services::GetZonesRequest {})
        .await
        .unwrap();
    let inner = resp.into_inner();
    assert!(
        inner.zones.iter().any(|z| z.name == zone.name),
        "expected zone '{}' to be present, got: {:?}",
        zone.name,
        inner.zones.iter().map(|z| &z.name).collect::<Vec<_>>()
    );
}

#[tokio::test]
#[serial(zone_pairs)]
async fn swap_zones_pairs_happy_path_returns_no_error() {
    let mut client = connect(&shared_server().socket).await;
    client
        .swap_zone_pairs(ngfw::proto::services::SwapZonePairsRequest {
            zone_pairs: vec![ngfw::proto::config::ZonePair {
                id: Uuid::now_v7().into(),
                src_zone_id: Uuid::now_v7().into(),
                dst_zone_id: Uuid::now_v7().into(),
                default_policy: Default::default(),
            }],
        })
        .await
        .unwrap();
}

#[tokio::test]
#[serial(zone_pairs)]
async fn fetch_zone_pairs_returns_ok() {
    let mut client = connect(&shared_server().socket).await;
    let zone_pair = ngfw::proto::config::ZonePair {
        id: Uuid::now_v7().into(),
        src_zone_id: Uuid::now_v7().into(),
        dst_zone_id: Uuid::now_v7().into(),
        default_policy: Default::default(),
    };
    client
        .swap_zone_pairs(ngfw::proto::services::SwapZonePairsRequest {
            zone_pairs: vec![zone_pair.clone()],
        })
        .await
        .unwrap();
    let resp = client
        .get_zone_pairs(ngfw::proto::services::GetZonePairsRequest {})
        .await
        .unwrap();
    let inner = resp.into_inner();
    assert!(
        inner.zone_pairs.iter().any(|zp| zp.id == zone_pair.id),
        "expected zone pair with id '{}' to be present, got: {:?}",
        zone_pair.id,
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
                event_socket_path: "./sockets/firewall.sock".into(),
                query_socket_path: "/tmp/test-query-shared.sock".into(),
                pki_dir: "/tmp/pki".into(),
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
        event_socket_path: "./sockets/firewall.sock".into(),
        query_socket_path: "/tmp/test-query-shared.sock".into(),
        pki_dir: "/tmp/pki".into(),
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
