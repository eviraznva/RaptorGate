use std::sync::Arc;
use std::time::Duration;

use raptorgate_testkit::{
    event, event_capture_concurrency_mutex, physical_zone_interface, set_event_capture,
    ConfigBundleBuilder, Event, EventCapture, EventKind, PacketsScenario, PipelineOutcome,
    Scenario, ScenarioRunError, SocketV4, TestDaemon, icmp_echo_ipv4,
    smoke_tcp_allow_warn_bundle,
};
use uuid::Uuid;
use tokio::time::timeout;

fn drop_tcp_bundle() -> ngfw::proto::services::ConfigBundle {
    use ngfw::proto::common::DefaultPolicy;
    use ngfw::proto::config::{Rule, Zone, ZonePair};

    let z1 = Uuid::now_v7();
    let z2 = Uuid::now_v7();
    let zp = Uuid::now_v7();
    let zi1 = Uuid::now_v7();
    let zi2 = Uuid::now_v7();

    let zones = vec![
        Zone {
            id: Uuid::nil().to_string(),
            name: "default".to_string(),
        },
        Zone {
            id: z1.to_string(),
            name: "zone1".to_string(),
        },
        Zone {
            id: z2.to_string(),
            name: "zone2".to_string(),
        },
    ];

    let zone_pairs = vec![ZonePair {
        id: zp.to_string(),
        src_zone_id: z1.to_string(),
        dst_zone_id: z2.to_string(),
        default_policy: DefaultPolicy::Unspecified as i32,
    }];

    let zone_interfaces = vec![
        physical_zone_interface(zi1, &z1.to_string(), "eth1", true),
        physical_zone_interface(zi2, &z2.to_string(), "eth2", true),
    ];

    let rules = vec![Rule {
        id: Uuid::now_v7().to_string(),
        name: "zone1-to-zone2".to_string(),
        zone_pair_id: zp.to_string(),
        priority: 0,
        content: r#"
            match protocol {
              =icmp: verdict drop_warn "icmp dropped"
              =tcp: verdict drop_warn "tcp dropped"
              =udp: verdict drop_warn "udp dropped"
            }
          "#
        .to_string(),
        smtp_matchers: None,
    }];

    ConfigBundleBuilder::new()
        .with_zones(zones)
        .with_zone_pairs(zone_pairs)
        .with_zone_interfaces(zone_interfaces)
        .with_rules(rules)
        .build()
}

#[tokio::test]
async fn packets_expect_packet_without_send() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(smoke_tcp_allow_warn_bundle())
        .build()
        .await
        .expect("test daemon");

    let res = PacketsScenario::new()
        .expect_packet(PipelineOutcome::Forward)
        .run(&td, &cap)
        .await;

    set_event_capture(None);

    assert!(matches!(res, Err(ScenarioRunError::ExpectPacketWithoutSend)));
}

#[tokio::test]
async fn tcp_expect_packet_without_send() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(smoke_tcp_allow_warn_bundle())
        .build()
        .await
        .expect("test daemon");
    let client = SocketV4 {
        ip: [192, 168, 10, 10],
        port: 40_000,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 20],
        port: 25,
    };

    let res = Scenario::tcp(client, server)
        .expect_packet(PipelineOutcome::Forward)
        .run(&td, &cap)
        .await;

    set_event_capture(None);

    assert!(matches!(res, Err(ScenarioRunError::ExpectPacketWithoutSend)));
}

#[tokio::test]
async fn packet_outcome_mismatch_reports_index() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let bundle = drop_tcp_bundle();
    let td = TestDaemon::builder()
        .with_bundle(bundle)
        .build()
        .await
        .expect("test daemon");

    let raw1 = icmp_echo_ipv4([192, 168, 10, 10], [192, 168, 20, 20]);
    let raw2 = icmp_echo_ipv4([192, 168, 10, 11], [192, 168, 20, 21]);

    let res = Scenario::packets()
        .on_iface("eth1")
        .send(raw1)
        .send(raw2)
        .expect_packet(PipelineOutcome::Forward)
        .run(&td, &cap)
        .await;

    set_event_capture(None);

    let Err(ScenarioRunError::PacketOutcome { send_index, .. }) = res else {
        panic!("expected PacketOutcome error");
    };
    assert_eq!(send_index, 1);
}

#[tokio::test]
#[ignore = "FIXME: there's something broken with tcp events"]
async fn tcp_session_emits_estabilished_event() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(smoke_tcp_allow_warn_bundle())
        .build()
        .await
        .expect("test daemon");
    let client = SocketV4 {
        ip: [192, 168, 10, 10],
        port: 40_000,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 20],
        port: 25,
    };

    let expect_event = event!(|e: &Event| {
        matches!(
            &e.kind,
            EventKind::TcpSessionEstabilished { .. }
        )
    });

    let res = timeout(
        Duration::from_secs(2),
        Scenario::tcp(client, server)
            .open()
            .expect_event(expect_event)
            .run(&td, &cap),
    )
    .await;

    set_event_capture(None);

    match res {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("scenario failed: {err}"),
        Err(_) => panic!("timed out waiting for event"),
    }
}
