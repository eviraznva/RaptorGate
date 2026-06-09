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
    // SSH_MSG_KEXINIT: padding_length(4) + msg_type(20) + 16-byte cookie (zeros) +
    // 10 empty name-lists + first_kex_packet_follows=0 + reserved=0 + padding(4).
    let mut body = Vec::with_capacity(67);
    body.push(4); // padding_length
    body.push(20); // msg_type
    body.extend_from_slice(&[0u8; 16]); // cookie
    for _ in 0..10 {
        body.extend_from_slice(&0u32.to_be_bytes());
    }
    body.push(0); // first_kex_packet_follows
    body.extend_from_slice(&[0u8; 4]); // reserved
    body.extend_from_slice(&[0u8; 4]); // padding
    ssh_packet(&body)
}

fn dh_init_minimal() -> Vec<u8> {
    // SSH_MSG_KEXDH_INIT: padding_length(4) + msg_type(30) + mpint e=empty + padding(4).
    let mut body = Vec::with_capacity(10);
    body.push(4); // padding_length
    body.push(30); // msg_type
    body.extend_from_slice(&0u32.to_be_bytes()); // e = empty string
    body.extend_from_slice(&[0u8; 4]); // padding
    ssh_packet(&body)
}

fn dh_reply_minimal() -> Vec<u8> {
    // SSH_MSG_KEXDH_REPLY: padding_length(4) + msg_type(31) + 3 empty strings + padding(4).
    let mut body = Vec::with_capacity(17);
    body.push(4); // padding_length
    body.push(31); // msg_type
    body.extend_from_slice(&0u32.to_be_bytes()); // host_key
    body.extend_from_slice(&0u32.to_be_bytes()); // f
    body.extend_from_slice(&0u32.to_be_bytes()); // signature
    body.extend_from_slice(&[0u8; 4]); // padding
    ssh_packet(&body)
}

fn new_keys() -> Vec<u8> {
    // SSH_MSG_NEWKEYS: padding_length(4) + msg_type(21) + padding(4).
    let body = vec![4u8, 21, 0, 0, 0, 0];
    ssh_packet(&body)
}

fn ext_info() -> Vec<u8> {
    // SSH_MSG_EXT_INFO: padding_length(4) + msg_type(7) + nr_extensions=0 + padding(4).
    let body = vec![4u8, 7, 0, 0, 0, 0, 0, 0, 0, 0];
    ssh_packet(&body)
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
    body.push(4); // padding_length
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
    body.extend_from_slice(&[0u8; 4]); // padding
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

#[tokio::test]
async fn ssh_l4_stage_forwards_ext_info_before_server_newkeys() {
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
        SocketV4 { ip: [192, 168, 10, 52], port: 40_124 },
        SocketV4 { ip: [192, 168, 20, 24], port: 22 },
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
    .client_sends(&ext_info())
    .expect_packet(Expectation::Disposition(PacketDispositionOutcome::Forward))
    .server_sends(&new_keys())
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .expect_event(expect_ssh_event)
    .run_v2(&td, &cap)
    .await
    .expect("ssh scenario");
    set_event_capture(None);
}

const CLIENT_KEXINIT_PART1_HEX: &str = "000005fc0714f07b23c9c235d3643352984a654fa14200000131736e747275703736317832353531392d736861353132406f70656e7373682e636f6d2c637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6578742d696e666f2d632c6b65782d7374726963742d632d763030406f70656e7373682e636f6d000001cf7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703338342d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703532312d636572742d763031406f70656e7373682e636f6d2c736b2d7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c736b2d65636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3531322d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3235362d636572742d763031406f70656e7373682e636f6d2c7373682d656432353531392c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c736b2d7373682d65643235353139406f70656e7373682e636f6d2c736b2d65636473612d736861322d6e69737470323536406f70656e7373682e636f6d2c7273612d736861322d3531322c7273612d736861322d3235360000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c68";

const CLIENT_KEXINIT_PART2_HEX: &str = "6d61632d736861310000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000000000000000000000000000000000000000";

const SERVER_KEXINIT_HEX: &str = "0000045c07142c451d1cb2ab9bce0fd4d048b2eef67100000131736e747275703736317832353531392d736861353132406f70656e7373682e636f6d2c637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6578742d696e666f2d732c6b65782d7374726963742d732d763030406f70656e7373682e636f6d000000397273612d736861322d3531322c7273612d736861322d3235362c65636473612d736861322d6e697374703235362c7373682d656432353531390000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d0000000000000000000000000000000000000000";

const CLIENT_DH_INIT_HEX: &str = "000004b4081e000004a696d4fc4c77b2ff6ecbb56f6f2994233d0539eccf6044f1fd22ea596bce3b4e1c2d0ae5896f04d785c4b1f254b99488428b8ff3b229c6e7b80ff60a6da684058f4a3922bc86ed4d5383fdeb993218680762f719ff0aaa064bc147bdb31fc04e8463921cbd9fa646802040d91af2769066f6977de5afd3cf62e35ea484bcb87473cbe84c2021e9add886aa095b0ed0248351972819eca0297e12e75ea706e7b8ce77f38dc883efd2a895fdb26517d1a9330ede01f2a3035d7c613ceaaee73a8a092a44668b006260dc321dcaca6dd692ee9536d7897240bf646cd6c2d49187faa61e2ec3971a33737e00adf6f8f8cb28c8c030e8f4eb93aec94edde9d2a5b2be2703b0f816566e491ddbb2b860ff42bdaca15d11a202b9282375aca586fcd00c18267605fa62a546764c5dfc668f0b7d6c9232a3983501db8f6099955ad6f1a652d68e20b123eacf3d39c92cf3f3ea82b952a2ac4fc6634de2f2f5a51634c2ffd782d1da36a1594fecf5981e0ed01f10c343522fb5c0d905ce85e5c7a72b7ae039ba858576e75d8a1bf3f2b079a6b8d7ab2dc95a8b7c3d4317c387c917ccd8e3ce1e60e100785a6a0b9df294da07d9e1cb6d280337b78845b842c0e6a43cfbfe49787b64ccc6e32f939afa874e09ef8ac23123da03bf2283cf2b8de94c2eb115c34a0c2ed2606718bfd21b3e662c27840ba404f54d8ca444d219395002d65ddf05bf8219ca10e0db7a2fe8b67cb222a1941e18980816555bd44ed8a7a2b59f994c9d7b277d294c726aba42a8cfe9be4eb0d81001e91360f09f151504c7241d35d6682d44780799e4913ef97df1a04779357a4881371793520fe9c8824bc9af9f087211b0582f2d80b80e10f99bdcb7080bb11d127da48e7633c9686fef18a640122d08605b594aaef6804a17ab60f95b218add285c0817b0c2316f5a4b8f045921b641cc0e02a726174c82d1a417fd8cd335292037c367e01fc041b98f806ce7b78671a6dc83a1775ca0eb74f98db14cfa846898657e132d125453507dc0145f08172e2e1ee8a05d8ca242405e65b7740c96d8bb6434df04080475f90e9c46219af683efdb1f73fcd43660cce6f2a03e91530e1d82a15781d3b582f69bc6dcd5fd0b66fb441af3902753ccf9710f7cf4f623a250196ff6c56a289ad0507d2afbf8f7b3a89d92b8294fea7dd37bf140e1b79ccfe07ad25b54a77d700c47e805ccf16dfd9f7ae255ceab01926357402d4dc89657e6f3f82967c4ecda9e0312d3354ee77cbad1115669ee2ce903d5f2109f0530404f53a7a55fd7c242d72dc310c5092b1dadb7757177cb87697c78624ad8809b63ef35ca5fbe0a2790964e94d98d858b7bcf4ebeb6229513c8612e7b1c196f6b4359de4cc5f6d1391475b13ba57e2b41707c7b0a580c7f3b3986a03085dec9c446df78d955da71a403613e5be89426ee6abb290eeea0c5c4e3fa219cb3c4425f49fbf010be025f78067489f8ae8fc4b9d8a996924abd98d819ffb35ebc7aea89dedfd70d456eb76ca7a0462901274fb1d114150bc30410ee839932713403f2e0aa87bd3e902856715c4356f0c5f3554606ab3fbc7f2779be5faa224d9f5a3d7a108a65bb251377a2c6329537281ec6f96ccf9e2a06410c7f157542493c46125fc29b55fd35ce90da109972eae03a80c16b367b1b510000000000000000";

#[tokio::test]
async fn ssh_replays_pcap_fragmented_handshake() {
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

    let client_banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.16\r\n";
    let server_banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.16\r\n";
    let client_kexinit_part1 = hex::decode(CLIENT_KEXINIT_PART1_HEX).expect("valid hex for part1");
    let client_kexinit_part2 = hex::decode(CLIENT_KEXINIT_PART2_HEX).expect("valid hex for part2");
    let server_kexinit = hex::decode(SERVER_KEXINIT_HEX).expect("valid hex for server kexinit");
    let client_dh_init = hex::decode(CLIENT_DH_INIT_HEX).expect("valid hex for dh init");

    Scenario::tcp(
        SocketV4 { ip: [192, 168, 10, 10], port: 45896 },
        SocketV4 { ip: [192, 168, 20, 10], port: 22 },
    )
    .open()
    .client_sends(client_banner)
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .server_sends(server_banner)
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .client_sends(&client_kexinit_part1)
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .client_sends(&client_kexinit_part2)
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .server_sends(&server_kexinit)
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .client_sends(&client_dh_init)
    .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
    .expect_event(expect_ssh_event)
    .run_v2(&td, &cap)
    .await
    .expect("ssh pcap replay scenario");
    set_event_capture(None);
}
