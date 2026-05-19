use std::time::SystemTime;

use ngfw::dpi::{AppProto, DpiClassifier, DpiContext};
use ngfw::tls::decrypted_flow::{DecryptedDpiStage, DecryptedFlowContext, DecryptedFlowStage};
use ngfw::tls::inspection_relay::{Direction, InspectionMode, SessionMeta};

fn sample_meta() -> SessionMeta {
    SessionMeta {
        session_id: uuid::Uuid::now_v7(),
        peer: "192.168.20.10:53120".parse().unwrap(),
        server: "142.250.186.4:443".parse().unwrap(),
        original_dst: "142.250.186.4:443".parse().unwrap(),
        sni: Some("example.com".into()),
        alpn: Some(b"http/1.1".to_vec()),
        client_side_interface: Some("eth1".into()),
        server_side_interface: Some("eth0".into()),
        mode: InspectionMode::Outbound,
    }
}

#[tokio::test]
async fn decrypted_dpi_stage_classifies_http_without_packet_context() {
    let mut ctx = DecryptedFlowContext::new(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        DpiContext {
            decrypted: true,
            src_port: Some(53120),
            dst_port: Some(443),
            ..Default::default()
        },
        Direction::ClientToServer,
        sample_meta(),
        SystemTime::UNIX_EPOCH,
        None,
    );
    let stage = DecryptedDpiStage::new(std::sync::Arc::new(DpiClassifier::new()));

    stage.process(&mut ctx).await;

    assert_eq!(ctx.dpi.app_proto, Some(AppProto::Http));
    assert_eq!(ctx.dpi.http_host.as_deref(), Some("example.com"));
    assert!(ctx.dpi.decrypted);
    assert_eq!(ctx.src.port(), 53120);
    assert_eq!(ctx.dst.port(), 443);
}
