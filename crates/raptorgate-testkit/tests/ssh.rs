use std::sync::Arc;
use raptorgate_testkit::{
    event, event_capture_concurrency_mutex, set_event_capture, smoke_tcp_allow_warn_bundle,
    EventCapture, Expectation, PacketDispositionOutcome, PipelineOutcome, Scenario, SocketV4,
    TestDaemon,
};

// SSH client (OpenSSH 9.6p1) ↔ server (OpenBSD 9.6 sshd) full-handshake payloads.
//
// Wire format: 4-byte big-endian length prefix + SSH packet body, per RFC 4253 §6.
// Banners are NOT length-prefixed; the SshPacketAssembler scans for '\n' and drains
// the line itself (see crates/raptorgate/src/dpi/ssh.rs:240-246).
fn kex_init_minimal() -> Vec<u8> {
    // msg_type=20 (SSH_MSG_KEXINIT) + 16-byte cookie (zeros) +
    // 10 name-lists (each length=0) + first_kex_packet_follows=0 + reserved=0.
    let mut body = Vec::with_capacity(62);
    body.push(20);
    body.extend_from_slice(&[0u8; 16]);
    for _ in 0..10 {
        body.extend_from_slice(&0u32.to_be_bytes());
    }
    body.push(0);
    body.extend_from_slice(&[0u8; 4]);
    ssh_packet(&body)
}

fn dh_init_minimal() -> Vec<u8> {
    // msg_type=30 (SSH_MSG_KEXDH_INIT) + mpint e=empty.
    let mut body = Vec::with_capacity(5);
    body.push(30);
    body.extend_from_slice(&0u32.to_be_bytes());
    ssh_packet(&body)
}

fn dh_reply_minimal() -> Vec<u8> {
    // msg_type=31 (SSH_MSG_KEXDH_REPLY) + string host_key=empty + mpint f=empty
    // + string signature=empty.
    let mut body = Vec::with_capacity(13);
    body.push(31);
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    ssh_packet(&body)
}

fn new_keys() -> Vec<u8> {
    // msg_type=21 (SSH_MSG_NEWKEYS).
    ssh_packet(&[21])
}

fn ssh_packet(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn name_list(names: &[&str]) -> Vec<u8> {
    let joined = names.join(",");
    let mut out = Vec::with_capacity(4 + joined.len());
    out.extend_from_slice(&(joined.len() as u32).to_be_bytes());
    out.extend_from_slice(joined.as_bytes());
    out
}

// Algorithm name lists that OpenSSH 9.6p1 (client) advertises by default
// (DEFAULT_KEX / DEFAULT_PK / DEFAULT_CTR_CIPHERS / DEFAULT_MAC, see upstream
// ssh.c and sshd.c). The "none" compression entry is the OpenSSH default.
const OPENSSH_96_KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group18-sha512",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "sntrup761x25519-sha512@openssh.com",
];
const OPENSSH_96_PK: &[&str] = &[
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-ed25519",
];
const OPENSSH_96_CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
];
const OPENSSH_96_MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
];
// OpenBSD 9.6 sshd default kex list — same as the client except the
// post-quantum hybrid is not enabled in OpenBSD's portable build.
const OPENBSD_96_SSHD_KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group18-sha512",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
];

fn real_openssh_client_kex_init() -> Vec<u8> {
    real_kex_init(OPENSSH_96_KEX, OPENSSH_96_PK, OPENSSH_96_CIPHERS, OPENSSH_96_MACS)
}

fn real_openssh_sshd_kex_init() -> Vec<u8> {
    real_kex_init(OPENBSD_96_SSHD_KEX, OPENSSH_96_PK, OPENSSH_96_CIPHERS, OPENSSH_96_MACS)
}

fn real_kex_init(
    kex_algs: &[&str],
    pk_algs: &[&str],
    ciphers: &[&str],
    macs: &[&str],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(20); // SSH_MSG_KEXINIT
    body.extend_from_slice(&[0u8; 16]); // cookie
    body.extend(name_list(kex_algs));
    body.extend(name_list(pk_algs));
    body.extend(name_list(ciphers));
    body.extend(name_list(ciphers));
    body.extend(name_list(macs));
    body.extend(name_list(macs));
    body.extend(name_list(&["none"]));
    body.extend(name_list(&["none"]));
    body.extend(name_list(&[]));
    body.extend(name_list(&[]));
    body.push(0); // first_kex_packet_follows
    body.extend_from_slice(&[0u8; 4]); // reserved
    ssh_packet(&body)
}

#[tokio::test]
async fn ssh_l4_stage_forwards_full_handshake() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));
    let td = TestDaemon::builder()
        .with_bundle(smoke_tcp_allow_warn_bundle())
        .build()
        .await
        .expect("test daemon");
    let expect_ssh_event = event!(|e: &raptorgate_testkit::Event| matches!(
        &e.kind,
        raptorgate_testkit::EventKind::DecidedAppProtocol { protocol, .. }
            if *protocol == ngfw::l4::AppProto::Ssh
    ));
    Scenario::tcp(
        SocketV4 { ip: [192, 168, 10, 50], port: 40_122 },
        SocketV4 { ip: [192, 168, 20, 22], port: 22 },
    )
    .open()
    .client_sends(b"SSH-2.0-OpenSSH_8.9\r\n")
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .server_sends(b"SSH-2.0-dropbear_2022.83\r\n")
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .client_sends(&kex_init_minimal())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .server_sends(&kex_init_minimal())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .client_sends(&dh_init_minimal())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .server_sends(&dh_reply_minimal())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .client_sends(&new_keys())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .server_sends(&new_keys())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .expect_event(expect_ssh_event)
    .run_v2(&td, &cap)
    .await
    .expect("ssh scenario");
    set_event_capture(None);
}

#[tokio::test]
async fn ssh_l4_stage_forwards_real_openssh_96_handshake() {
    let _guard = event_capture_concurrency_mutex().lock().await;
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));
    let td = TestDaemon::builder()
        .with_bundle(smoke_tcp_allow_warn_bundle())
        .build()
        .await
        .expect("test daemon");
    let expect_ssh_event = event!(|e: &raptorgate_testkit::Event| matches!(
        &e.kind,
        raptorgate_testkit::EventKind::DecidedAppProtocol { protocol, .. }
            if *protocol == ngfw::l4::AppProto::Ssh
    ));
    Scenario::tcp(
        SocketV4 { ip: [192, 168, 10, 51], port: 40_123 },
        SocketV4 { ip: [192, 168, 20, 23], port: 22 },
    )
    .open()
    .client_sends(b"SSH-2.0-OpenSSH_8.9\r\n")
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .server_sends(b"SSH-2.0-dropbear_2022.83\r\n")
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .client_sends(&real_openssh_client_kex_init())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .server_sends(&real_openssh_sshd_kex_init())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .client_sends(&dh_init_minimal())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .server_sends(&dh_reply_minimal())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .client_sends(&new_keys())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .server_sends(&new_keys())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .expect_event(expect_ssh_event)
    .run_v2(&td, &cap)
    .await
    .expect("ssh scenario");
    set_event_capture(None);
}

// #[tokio::test]
// async fn ssh_l4_stage_forwards_ext_info_before_server_newkeys() {
//     let _guard = event_capture_concurrency_mutex().lock().await;
//     let cap = Arc::new(EventCapture::new());
//     set_event_capture(Some(cap.clone()));
//     let td = TestDaemon::builder()
//         .with_bundle(smoke_tcp_allow_warn_bundle())
//         .build()
//         .await
//         .expect("test daemon");
//     let expect_ssh_event = event!(|e: &raptorgate_testkit::Event| matches!(
//         &e.kind,
//         raptorgate_testkit::EventKind::DecidedAppProtocol { protocol, .. }
//             if *protocol == ngfw::l4::AppProto::Ssh
//     ));
//     Scenario::tcp(
//         SocketV4 { ip: [192, 168, 10, 52], port: 40_124 },
//         SocketV4 { ip: [192, 168, 20, 24], port: 22 },
//     )
//     .open()
//     .client_sends(b"SSH-2.0-OpenSSH_8.9\r\n")
//     .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
//     .server_sends(b"SSH-2.0-dropbear_2022.83\r\n")
//     .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
//     .client_sends(&real_openssh_client_kex_init())
//     .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
//     .server_sends(&real_openssh_sshd_kex_init())
//     .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
//     .client_sends(&dh_init_minimal())
//     .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
//     .server_sends(&dh_reply_minimal())
//     .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
//     .client_sends(&new_keys())
//     .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
//     .client_sends(b"\x00\x00\x00\x01\xff")
//     .expect_packet(Expectation::Disposition(PacketDispositionOutcome::Forward))
//     .server_sends(&new_keys())
//     .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
//     .expect_event(expect_ssh_event)
//     .run_v2(&td, &cap)
//     .await
//     .expect("ssh scenario");
//     set_event_capture(None);
// }
