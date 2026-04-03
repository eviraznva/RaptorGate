use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::sync::OnceLock;

use ngfw::config::AppConfig;
use ngfw::data_plane::nat::NatEngine;
use ngfw::data_plane::tcp_session_tracker::TcpSessionTracker;
use ngfw::policy::provider::DiskPolicyProvider;
use ngfw::proto::config::Rule;
use ngfw::proto::services::{GetPoliciesRequest, SwapPoliciesRequest};
use ngfw::proto::services::firewall_query_service_client::FirewallQueryServiceClient;
use ngfw::query_server::{QueryHandler, QueryServer};
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
                let config = AppConfig::from_env().expect("failed to load config");
                let policy = DiskPolicyProvider::from_loaded(&config)
                    .await
                    .expect("failed to load policy provider");

                let handler = QueryHandler {
                    tcp_tracker: TcpSessionTracker::new(),
                    nat_engine: Arc::new(Mutex::new(NatEngine::new(&None, HashMap::new()))),
                    policy_store: Arc::new(policy),
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
async fn swap_config_happy_path_returns_no_error() {
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
async fn swap_config_error_path_returns_error_message() {
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
        .swap_policies(SwapPoliciesRequest { rules: vec![rule.clone()] })
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
