use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ngfw::data_plane::nat::NatEngine;
use ngfw::data_plane::tcp_session_tracker::TcpSessionTracker;
use ngfw::policy::{Policy, parse_rule_tree};
use ngfw::policy::provider::MockPolicySwapper;
use ngfw::proto::config::Rule;
use ngfw::proto::services::SwapConfigRequest;
use ngfw::proto::services::firewall_query_service_client::FirewallQueryServiceClient;
use ngfw::query_server::{QueryHandler, QueryServer};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn unique_socket() -> String {
    format!("/tmp/test-query-{}.sock", Uuid::now_v7())
}

fn make_mock_policy_swap() -> MockPolicySwapper {
    let mut mock = MockPolicySwapper::new();

    mock.expect_swap_policies()
        .returning(|policies: Vec<Policy>| {
            Box::pin(async move {
                if policies.len() == 1 && policies[0].name == "correct" && policies[0].priority == 0 {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("invalid raptorlang"))
                }
            })
        });

    mock
}
fn make_handler() -> QueryHandler<MockPolicySwapper> {
    let policy = make_mock_policy_swap();
    QueryHandler {
        tcp_tracker: TcpSessionTracker::new(),
        nat_engine: Arc::new(Mutex::new(NatEngine::new(&None, HashMap::new()))),
        policy_store: policy.into(), // TODO: mock this at some point
    }
}

async fn start_server(socket: &str) -> CancellationToken {
    let shutdown = CancellationToken::new();
    let server = QueryServer::new(make_handler(), socket, shutdown.clone());
    tokio::spawn(server.serve());
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown
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
async fn validate_config_happy_path_returns_no_error() {
    let socket = unique_socket();
    let shutdown = start_server(&socket).await;
    let mut client = connect(&socket).await;

    let resp = client
        .swap_config(SwapConfigRequest {
            rules: vec![Rule {
                id: "rule-1".into(),
                name: "correct".into(),
                zone_pair_id: "zone-a-b".into(),
                priority: 0,
                content: "match ip_ver { =v4: match protocol { |(=icmp =tcp): verdict allow } = v6: verdict drop }".into(),
            }],
        })
    .await;

    assert!(resp.is_ok());
    shutdown.cancel();
}

#[tokio::test]
async fn validate_config_error_path_returns_error_message() {
    let socket = unique_socket();
    let shutdown = start_server(&socket).await;
    let mut client = connect(&socket).await;

    let resp = client
        .swap_config(SwapConfigRequest {
            rules: vec![Rule {
                id: "rule-2".into(),
                name: "incorrect".into(),
                zone_pair_id: "zone-a-b".into(),
                priority: 1,
                content: "this is not valid raptorlang".into(),
            }],
        })
        .await;

    assert!(resp.is_err());
    shutdown.cancel();
}
