use std::sync::Arc;

use ngfw::events::Event;
use ngfw::proto::config::{SmtpMatch, SmtpMatchAction, SmtpMatchers};
use ngfw::proto::events::{ConntrackPacketDirection, TcpSessionState};

use crate::{
    conntrack_queries::ConntrackSnapshotExt,
    event_capture_concurrency_mutex, event,
    outcomes::{check_legacy_pipeline, check_v2_pipeline, Expectation, PipelineOutcome},
    scenario::{Scenario, SocketV4, TcpSessionV4},
    set_event_capture,
    smoke_icmp_allow_warn_bundle,
    test_bundles::{
        default_zone_dual_iface_dst_port_rule_bundle, dual_zone_allow_ipv4_bundle,
        dual_zone_allow_ipv4_smtp_bundle,
    },
    EventCapture, EventKind, TestDaemon,
};

fn smtp_sender_allow_test_local() -> SmtpMatchers {
    SmtpMatchers {
        sender: vec![SmtpMatch {
            regex: ".*@test\\.local".into(),
            on_match: SmtpMatchAction::Allow as i32,
        }],
        recipient: vec![],
        message: vec![],
    }
}

fn smtp_recipient_allow_test_local() -> SmtpMatchers {
    SmtpMatchers {
        sender: vec![],
        recipient: vec![SmtpMatch {
            regex: ".*@test\\.local".into(),
            on_match: SmtpMatchAction::Allow as i32,
        }],
        message: vec![],
    }
}

fn smtp_message_allow_deny_dotall() -> SmtpMatchers {
    SmtpMatchers {
        sender: vec![],
        recipient: vec![],
        message: vec![
            SmtpMatch {
                regex: "(?s).*hello.*".into(),
                on_match: SmtpMatchAction::Allow as i32,
            },
            SmtpMatch {
                regex: "(?s).*world.*".into(),
                on_match: SmtpMatchAction::Deny as i32,
            },
        ],
    }
}

fn smtp_state_chain_preds() -> Vec<ngfw::events::EventPredicate> {
    [
        "GreetingReceived",
        "Ready",
        "EnvelopeOpen",
        "ReciepientSet",
        "Data(Await354)",
        "Data(Collecting)",
        "Data(Complete)",
        "Ready",
    ]
    .into_iter()
    .map(|want| {
        let want = want.to_string();
        event!(move |e: &Event| {
            matches!(
                &e.kind,
                EventKind::SmtpSessionStateChanged { new_state, .. } if new_state == &want
            )
        })
    })
    .collect()
}

async fn smtp_minimal_exchange_scenario(
    td: &TestDaemon,
    cap: &Arc<EventCapture>,
    mail_from: &[u8],
    rcpt_to: &[u8],
    data_body: &[u8],
) -> Result<(), crate::scenario::ScenarioRunError> {
    let client = SocketV4 {
        ip: [192, 168, 10, 33],
        port: 41_002,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 13],
        port: 25,
    };

    let mut mail = Vec::from(b"MAIL FROM:<");
    mail.extend_from_slice(mail_from);
    mail.extend_from_slice(b">\r\n");

    let mut rcpt = Vec::from(b"RCPT TO:<");
    rcpt.extend_from_slice(rcpt_to);
    rcpt.extend_from_slice(b">\r\n");

    let mut data = Vec::new();
    data.extend_from_slice(data_body);
    if !data.ends_with(b"\r\n.\r\n") {
        if !data.ends_with(b"\n") {
            data.extend_from_slice(b"\r\n");
        }
        data.extend_from_slice(b".\r\n");
    }

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx ESMTP ready\r\n")
        .client_sends(b"EHLO client\r\n")
        .server_sends(b"250-client\r\n")
        .client_sends(&mail)
        .server_sends(b"250 2.1.0 OK\r\n")
        .client_sends(&rcpt)
        .server_sends(b"250 2.1.5 OK\r\n")
        .client_sends(b"DATA\r\n")
        .server_sends(b"354 go ahead\r\n")
        .client_sends(&data)
        .server_sends(b"250 2.0.0 queued\r\n")
        .run(td, cap)
        .await?;

    cap.wait_for_subsequence(&smtp_state_chain_preds()).await?;
    Ok(())
}

async fn smtp_minimal_exchange_scenario_v2(
    td: &TestDaemon,
    cap: &Arc<EventCapture>,
    mail_from: &[u8],
    rcpt_to: &[u8],
    data_body: &[u8],
) -> Result<(), crate::scenario::ScenarioRunError> {
    let client = SocketV4 {
        ip: [192, 168, 10, 33],
        port: 41_002,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 13],
        port: 25,
    };

    let mut mail = Vec::from(b"MAIL FROM:<");
    mail.extend_from_slice(mail_from);
    mail.extend_from_slice(b">\r\n");

    let mut rcpt = Vec::from(b"RCPT TO:<");
    rcpt.extend_from_slice(rcpt_to);
    rcpt.extend_from_slice(b">\r\n");

    let mut data = Vec::new();
    data.extend_from_slice(data_body);
    if !data.ends_with(b"\r\n.\r\n") {
        if !data.ends_with(b"\n") {
            data.extend_from_slice(b"\r\n");
        }
        data.extend_from_slice(b".\r\n");
    }

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx ESMTP ready\r\n")
        .client_sends(b"EHLO client\r\n")
        .server_sends(b"250-client\r\n")
        .client_sends(&mail)
        .server_sends(b"250 2.1.0 OK\r\n")
        .client_sends(&rcpt)
        .server_sends(b"250 2.1.5 OK\r\n")
        .client_sends(b"DATA\r\n")
        .server_sends(b"354 go ahead\r\n")
        .client_sends(&data)
        .server_sends(b"250 2.0.0 queued\r\n")
        .run_v2(td, cap)
        .await?;

    Ok(())
}

#[tokio::test]
async fn phase05_zone_policy_icmp_allow_warn_tcp_udp_drop_warn() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let bundle = smoke_icmp_allow_warn_bundle();
    let td = TestDaemon::builder()
        .with_bundle(bundle)
        .build()
        .await
        .expect("daemon");

    let raw_icmp = crate::icmp_echo_ipv4([192, 168, 10, 1], [192, 168, 20, 10]);
    let out_icmp = Box::pin(td
        .process_raw(raw_icmp, Arc::from("eth1")))
        .await;
    check_legacy_pipeline(&out_icmp, PipelineOutcome::Forwarded).expect("icmp forward");
    cap.wait_for_subsequence(&[event!(|e: &Event| {
        matches!(
            &e.kind,
            EventKind::PolicyWarning { message, verdict }
                if message == "icmp allowed" && verdict == &"allow"
        )
    })])
    .await
    .expect("icmp policy warning");

    let syn_only = TcpSessionV4::new(
        SocketV4 {
            ip: [192, 168, 10, 4],
            port: 44_444,
        },
        SocketV4 {
            ip: [192, 168, 20, 10],
            port: 4444,
        },
    );
    let out_tcp = Box::pin(
        td.process_raw(syn_only.syn_from_client(), Arc::from("eth1")),
    )
    .await;
    check_legacy_pipeline(&out_tcp, PipelineOutcome::Rejected).expect("tcp syn drop");
    cap.wait_for_subsequence(&[event!(|e: &Event| {
        matches!(
            &e.kind,
            EventKind::PolicyWarning { message, verdict }
                if message == "tcp dropped" && verdict == &"drop"
        )
    })])
    .await
    .expect("tcp policy warning");

    let udp = crate::UdpSessionV4::new(
        SocketV4 {
            ip: [192, 168, 10, 5],
            port: 50_000,
        },
        SocketV4 {
            ip: [192, 168, 20, 10],
            port: 5555,
        },
    );
    let out_udp = Box::pin(td.process_raw(
        udp.datagram_client_to_server(b"ping"),
        Arc::from("eth1"),
    ))
    .await;
    check_legacy_pipeline(&out_udp, PipelineOutcome::Rejected).expect("udp drop");
    cap.wait_for_subsequence(&[event!(|e: &Event| {
        matches!(
            &e.kind,
            EventKind::PolicyWarning { message, verdict }
                if message == "udp dropped" && verdict == &"drop"
        )
    })])
    .await
    .expect("udp policy warning");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_permissive_state_subsequence() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_bundle())
        .build()
        .await
        .expect("daemon");

    smtp_minimal_exchange_scenario(
        &td,
        &cap,
        b"user1@test.local",
        b"user2@test.local",
        b"Subject: t\r\n\r\nhello body\r\n",
    )
    .await
    .expect("smtp scenario");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_sender_allow_list_rst_on_bad_mail_from() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_smtp_bundle(smtp_sender_allow_test_local()))
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 34],
        port: 41_003,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 14],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hi\r\n")
        .client_sends(b"MAIL FROM:<x@test.remote>\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run(&td, &cap)
        .await
        .expect("deny sender");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_recipient_allow_list_rst_on_bad_rcpt() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_smtp_bundle(smtp_recipient_allow_test_local()))
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 35],
        port: 41_004,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 15],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hi\r\n")
        .client_sends(b"MAIL FROM:<a@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"RCPT TO:<b@test.remote>\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run(&td, &cap)
        .await
        .expect("deny rcpt");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_mixed_recipient_second_rcpt_denied() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_smtp_bundle(smtp_recipient_allow_test_local()))
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 36],
        port: 41_005,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 16],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hi\r\n")
        .client_sends(b"MAIL FROM:<a@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"RCPT TO:<b@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"RCPT TO:<c@test.remote>\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run(&td, &cap)
        .await
        .expect("mixed rcpt");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_message_dotall_allow_deny() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_smtp_bundle(smtp_message_allow_deny_dotall()))
        .build()
        .await
        .expect("daemon");

    smtp_minimal_exchange_scenario(
        &td,
        &cap,
        b"u@test.local",
        b"v@test.local",
        b"Subject: x\r\n\r\nhello there\r\n",
    )
    .await
    .expect("hello allow");

    let client = SocketV4 {
        ip: [192, 168, 10, 37],
        port: 41_006,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 17],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hi\r\n")
        .client_sends(b"MAIL FROM:<u@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"RCPT TO:<v@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"DATA\r\n")
        .server_sends(b"354 ok\r\n")
        .client_sends(b"hello line1\r\nline2 world\r\n.\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run(&td, &cap)
        .await
        .expect("hello world deny");

    let client = SocketV4 {
        ip: [192, 168, 10, 38],
        port: 41_007,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 18],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hi\r\n")
        .client_sends(b"MAIL FROM:<u@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"RCPT TO:<v@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"DATA\r\n")
        .server_sends(b"354 ok\r\n")
        .client_sends(b"Subject: x\r\n\r\ntesting alone\r\n.\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run(&td, &cap)
        .await
        .expect("no hello deny");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_mail_buffered_then_released_batch() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_bundle())
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 39],
        port: 41_008,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 19],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hello\r\n")
        .client_sends(b"MAIL FROM:<a@test.local>\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .server_sends(b"250 ok\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run(&td, &cap)
        .await
        .expect("smtp mail buffer release");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_dst_port_rule_allow_and_drop() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(default_zone_dual_iface_dst_port_rule_bundle())
        .build()
        .await
        .expect("daemon");

    let ok = Scenario::tcp(
        SocketV4 {
            ip: [192, 168, 20, 20],
            port: 50_001,
        },
        SocketV4 {
            ip: [192, 168, 10, 10],
            port: 12_346,
        },
    )
    .on_client_iface("eth2")
    .on_server_iface("eth1");

    ok.open()
        .run(&td, &cap)
        .await
        .expect("12346 allow");

    let blocked = Scenario::tcp(
        SocketV4 {
            ip: [192, 168, 20, 21],
            port: 50_002,
        },
        SocketV4 {
            ip: [192, 168, 10, 10],
            port: 12_345,
        },
    )
    .on_client_iface("eth2")
    .on_server_iface("eth1");

    blocked
        .open()
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Rejected))
        .run(&td, &cap)
        .await
        .expect("12345 drop");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_conntrack_tcp_established_after_handshake() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = Box::pin(TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_bundle())
        .build()
        .await
        .expect("daemon"));

    let s = TcpSessionV4::new(
        SocketV4 {
            ip: [192, 168, 10, 41],
            port: 41_010,
        },
        SocketV4 {
            ip: [192, 168, 20, 21],
            port: 12_340,
        },
    );
    let _ = Box::pin(td.process_raw(s.syn_from_client(), Arc::from("eth1"))).await;
    let _ = Box::pin(td.process_raw(s.syn_ack_from_server(), Arc::from("eth2"))).await;
    let _ = Box::pin(td.process_raw(s.ack_from_client(), Arc::from("eth1"))).await;
    let snap = td.conntrack_snapshot();
    assert!(
        snap.contains_flow_ipv4([192, 168, 10, 41], [192, 168, 20, 21]),
        "conntrack lists flow after handshake"
    );
    assert!(
        snap.established_flow_count() >= 1,
        "conntrack has established tcp"
    );

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_tcp_established_and_timewait_on_close() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_bundle())
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 40],
        port: 41_009,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 20],
        port: 12_345,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"hello\n")
        .client_fin()
        .server_ack()
        .server_fin()
        .client_final_ack()
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Reply,
                    previous_state: TcpSessionState::SynSent,
                    new_state: TcpSessionState::SynRecv,
                    ..
                }
            )
        }))
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Original,
                    previous_state: TcpSessionState::SynRecv,
                    new_state: TcpSessionState::Established,
                    ..
                }
            )
        }))
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Original,
                    previous_state: TcpSessionState::Established,
                    new_state: TcpSessionState::FinWait,
                    ..
                }
            )
        }))
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Reply,
                    previous_state: TcpSessionState::FinWait,
                    new_state: TcpSessionState::CloseWait,
                    ..
                }
            )
        }))
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Reply,
                    previous_state: TcpSessionState::CloseWait,
                    new_state: TcpSessionState::LastAck,
                    ..
                }
            )
        }))
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Original,
                    previous_state: TcpSessionState::LastAck,
                    new_state: TcpSessionState::TimeWait,
                    ..
                }
            )
        }))
        .run(&td, &cap)
        .await
        .expect("tcp lifecycle");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_zone_policy_icmp_allow_warn_tcp_udp_drop_warn_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let bundle = smoke_icmp_allow_warn_bundle();
    let td = TestDaemon::builder()
        .with_bundle(bundle)
        .build()
        .await
        .expect("daemon");

    let raw_icmp = crate::icmp_echo_ipv4([192, 168, 10, 1], [192, 168, 20, 10]);
    let out_icmp = Box::pin(td.process_raw_with_packet_id(raw_icmp, Arc::from("eth1"))).await;
    check_v2_pipeline(&out_icmp.output, PipelineOutcome::Forwarded).expect("icmp forward");

    let syn_only = TcpSessionV4::new(
        SocketV4 {
            ip: [192, 168, 10, 4],
            port: 44_444,
        },
        SocketV4 {
            ip: [192, 168, 20, 10],
            port: 4444,
        },
    );
    let out_tcp = Box::pin(
        td.process_raw_with_packet_id(syn_only.syn_from_client(), Arc::from("eth1")),
    )
    .await;
    check_v2_pipeline(&out_tcp.output, PipelineOutcome::Forwarded).expect("tcp syn drop");

    let udp = crate::UdpSessionV4::new(
        SocketV4 {
            ip: [192, 168, 10, 5],
            port: 50_000,
        },
        SocketV4 {
            ip: [192, 168, 20, 10],
            port: 5555,
        },
    );
    let out_udp = Box::pin(
        td.process_raw_with_packet_id(
            udp.datagram_client_to_server(b"ping"),
            Arc::from("eth1"),
        ),
    )
    .await;
    check_v2_pipeline(&out_udp.output, PipelineOutcome::Forwarded).expect("udp drop");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_permissive_state_subsequence_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_bundle())
        .build()
        .await
        .expect("daemon");

    smtp_minimal_exchange_scenario_v2(
        &td,
        &cap,
        b"user1@test.local",
        b"user2@test.local",
        b"Subject: t\r\n\r\nhello body\r\n",
    )
    .await
    .expect("smtp scenario");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_sender_allow_list_rst_on_bad_mail_from_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_smtp_bundle(smtp_sender_allow_test_local()))
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 34],
        port: 41_003,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 14],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hi\r\n")
        .client_sends(b"MAIL FROM:<x@test.remote>\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run_v2(&td, &cap)
        .await
        .expect("deny sender");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_recipient_allow_list_rst_on_bad_rcpt_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_smtp_bundle(smtp_recipient_allow_test_local()))
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 35],
        port: 41_004,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 15],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hi\r\n")
        .client_sends(b"MAIL FROM:<a@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"RCPT TO:<b@test.remote>\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run_v2(&td, &cap)
        .await
        .expect("deny rcpt");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_mixed_recipient_second_rcpt_denied_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_smtp_bundle(smtp_recipient_allow_test_local()))
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 36],
        port: 41_005,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 16],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hi\r\n")
        .client_sends(b"MAIL FROM:<a@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"RCPT TO:<b@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"RCPT TO:<c@test.remote>\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run_v2(&td, &cap)
        .await
        .expect("mixed rcpt");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_message_dotall_allow_deny_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_smtp_bundle(smtp_message_allow_deny_dotall()))
        .build()
        .await
        .expect("daemon");

    smtp_minimal_exchange_scenario_v2(
        &td,
        &cap,
        b"u@test.local",
        b"v@test.local",
        b"Subject: x\r\n\r\nhello there\r\n",
    )
    .await
    .expect("hello allow");

    let client = SocketV4 {
        ip: [192, 168, 10, 37],
        port: 41_006,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 17],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hi\r\n")
        .client_sends(b"MAIL FROM:<u@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"RCPT TO:<v@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"DATA\r\n")
        .server_sends(b"354 ok\r\n")
        .client_sends(b"hello line1\r\nline2 world\r\n.\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run_v2(&td, &cap)
        .await
        .expect("hello world deny");

    let client = SocketV4 {
        ip: [192, 168, 10, 38],
        port: 41_007,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 18],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hi\r\n")
        .client_sends(b"MAIL FROM:<u@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"RCPT TO:<v@test.local>\r\n")
        .server_sends(b"250 ok\r\n")
        .client_sends(b"DATA\r\n")
        .server_sends(b"354 ok\r\n")
        .client_sends(b"Subject: x\r\n\r\ntesting alone\r\n.\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run_v2(&td, &cap)
        .await
        .expect("no hello deny");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_mail_buffered_then_released_batch_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_bundle())
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 39],
        port: 41_008,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 19],
        port: 25,
    };

    Scenario::tcp(client, server)
        .open()
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .server_sends(b"220 mx\r\n")
        .client_sends(b"EHLO c\r\n")
        .server_sends(b"250 hello\r\n")
        .client_sends(b"MAIL FROM:<a@test.local>\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .server_sends(b"250 ok\r\n")
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run_v2(&td, &cap)
        .await
        .expect("smtp mail buffer release");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_dst_port_rule_allow_and_drop_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(default_zone_dual_iface_dst_port_rule_bundle())
        .build()
        .await
        .expect("daemon");

    let ok = Scenario::tcp(
        SocketV4 {
            ip: [192, 168, 20, 20],
            port: 50_001,
        },
        SocketV4 {
            ip: [192, 168, 10, 10],
            port: 12_346,
        },
    )
    .on_client_iface("eth2")
    .on_server_iface("eth1");

    ok.open()
        .run_v2(&td, &cap)
        .await
        .expect("12346 allow");

    let blocked = Scenario::tcp(
        SocketV4 {
            ip: [192, 168, 20, 21],
            port: 50_002,
        },
        SocketV4 {
            ip: [192, 168, 10, 10],
            port: 12_345,
        },
    )
    .on_client_iface("eth2")
    .on_server_iface("eth1");

    blocked
        .open()
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run_v2(&td, &cap)
        .await
        .expect("12345 drop");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_conntrack_tcp_established_after_handshake_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = Box::pin(
        TestDaemon::builder()
            .with_bundle(dual_zone_allow_ipv4_bundle())
            .build()
            .await
            .expect("daemon"),
    );

    let s = TcpSessionV4::new(
        SocketV4 {
            ip: [192, 168, 10, 41],
            port: 41_010,
        },
        SocketV4 {
            ip: [192, 168, 20, 21],
            port: 12_340,
        },
    );
    let _ = Box::pin(td.process_raw_with_packet_id(s.syn_from_client(), Arc::from("eth1"))).await;
    let _ = Box::pin(td.process_raw_with_packet_id(s.syn_ack_from_server(), Arc::from("eth2"))).await;
    let _ = Box::pin(td.process_raw_with_packet_id(s.ack_from_client(), Arc::from("eth1"))).await;
    let snap = td.conntrack_snapshot();
    assert!(
        snap.contains_flow_ipv4([192, 168, 10, 41], [192, 168, 20, 21]),
        "conntrack lists flow after handshake"
    );
    assert!(
        snap.established_flow_count() >= 1,
        "conntrack has established tcp"
    );

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_tcp_established_and_timewait_on_close_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_bundle())
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 40],
        port: 41_009,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 20],
        port: 12_345,
    };

    Scenario::tcp(client, server)
        .open()
        .server_sends(b"hello\n")
        .client_fin()
        .server_ack()
        .server_fin()
        .client_final_ack()
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Reply,
                    previous_state: TcpSessionState::SynSent,
                    new_state: TcpSessionState::SynRecv,
                    ..
                }
            )
        }))
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Original,
                    previous_state: TcpSessionState::SynRecv,
                    new_state: TcpSessionState::Established,
                    ..
                }
            )
        }))
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Original,
                    previous_state: TcpSessionState::Established,
                    new_state: TcpSessionState::FinWait,
                    ..
                }
            )
        }))
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Reply,
                    previous_state: TcpSessionState::FinWait,
                    new_state: TcpSessionState::CloseWait,
                    ..
                }
            )
        }))
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Reply,
                    previous_state: TcpSessionState::CloseWait,
                    new_state: TcpSessionState::LastAck,
                    ..
                }
            )
        }))
        .expect_event(event!(|e: &Event| {
            matches!(
                &e.kind,
                EventKind::TcpSessionSubstateChanged {
                    packet_direction: ConntrackPacketDirection::Original,
                    previous_state: TcpSessionState::LastAck,
                    new_state: TcpSessionState::TimeWait,
                    ..
                }
            )
        }))
        .run_v2(&td, &cap)
        .await
        .expect("tcp lifecycle");

    set_event_capture(None);
}


#[tokio::test]
async fn phase05_smtp_state_transitions() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_bundle())
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 50],
        port: 41_020,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 50],
        port: 25,
    };

    let mut scenario = Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx ESMTP ready\r\n")
        .client_sends(b"EHLO client\r\n");

    for pred in smtp_state_chain_preds() {
        scenario = scenario.expect_event(pred);
    }

    scenario
        .server_sends(b"250-client\r\n")
        .client_sends(b"MAIL FROM:<user1@test.local>\r\n")
        .server_sends(b"250 2.1.0 OK\r\n")
        .client_sends(b"RCPT TO:<user2@test.local>\r\n")
        .server_sends(b"250 2.1.5 OK\r\n")
        .client_sends(b"DATA\r\n")
        .server_sends(b"354 go ahead\r\n")
        .client_sends(b"Test email body\r\n.\r\n")
        .server_sends(b"250 2.0.0 queued\r\n")
        .run(&td, &cap)
        .await
        .expect("smtp state transitions");

    set_event_capture(None);
}

#[tokio::test]
async fn phase05_smtp_state_transitions_v2() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let td = TestDaemon::builder()
        .with_bundle(dual_zone_allow_ipv4_bundle())
        .build()
        .await
        .expect("daemon");

    let client = SocketV4 {
        ip: [192, 168, 10, 51],
        port: 41_021,
    };
    let server = SocketV4 {
        ip: [192, 168, 20, 51],
        port: 25,
    };

    let mut scenario = Scenario::tcp(client, server)
        .open()
        .server_sends(b"220 mx ESMTP ready\r\n")
        .client_sends(b"EHLO client\r\n");

    for pred in smtp_state_chain_preds() {
        scenario = scenario.expect_event(pred);
    }

    scenario
        .server_sends(b"250-client\r\n")
        .client_sends(b"MAIL FROM:<user1@test.local>\r\n")
        .server_sends(b"250 2.1.0 OK\r\n")
        .client_sends(b"RCPT TO:<user2@test.local>\r\n")
        .server_sends(b"250 2.1.5 OK\r\n")
        .client_sends(b"DATA\r\n")
        .server_sends(b"354 go ahead\r\n")
        .client_sends(b"Test email body\r\n.\r\n")
        .server_sends(b"250 2.0.0 queued\r\n")
        .run_v2(&td, &cap)
        .await
        .expect("smtp state transitions");

    set_event_capture(None);
}
