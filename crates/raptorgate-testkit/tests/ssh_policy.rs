use ngfw::dpi::ssh::policy::{
    compute_negotiated, OwnedKexInit, SshBannerInfo, SshDisconnectInfo, SshHost, SshHostKeyInfo,
    SshNegotiated,
};
use ngfw::policy::{
    parse_rule_tree, Policy, PolicyId, SshMatch, SshMatchAction, SshPolicy, SshReasonMatch,
};
use ngfw::rule_tree::RuleTree;
use ngfw::zones::ZonePairId;
use regex::bytes::Regex;
use uuid::Uuid;

fn ssh_match(regex: &str, action: SshMatchAction) -> SshMatch {
    SshMatch {
        regex: Regex::new(regex).unwrap(),
        on_match: action,
    }
}

fn reason_match(codes: &[u32], action: SshMatchAction) -> SshReasonMatch {
    SshReasonMatch {
        codes: codes.to_vec(),
        on_match: action,
    }
}

fn banner(host: SshHost, proto: &str, software: &str) -> SshBannerInfo {
    SshBannerInfo {
        host,
        proto_version: proto.as_bytes().to_vec(),
        software: software.as_bytes().to_vec(),
        comments: None,
    }
}

fn permissive_policy() -> SshPolicy {
    let allow_all = ssh_match(".*", SshMatchAction::Allow);
    SshPolicy {
        client_software: vec![allow_all.clone()],
        server_software: vec![allow_all.clone()],
        client_proto_version: vec![allow_all.clone()],
        server_proto_version: vec![allow_all.clone()],
        kex: vec![allow_all.clone()],
        host_key_alg: vec![allow_all.clone()],
        cipher: vec![allow_all.clone()],
        mac: vec![allow_all.clone()],
        compression: vec![allow_all.clone()],
        host_key_type: vec![allow_all],
        disconnect_reason: vec![],
    }
}

#[test]
fn client_software_allow_and_deny() {
    let allow_policy = SshPolicy {
        client_software: vec![ssh_match(r"OpenSSH_.*", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        client_software: vec![ssh_match(r"dropbear_.*", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(allow_policy.evaluate(&banner(SshHost::Client, "2.0", "OpenSSH_8.9")));
    assert!(!allow_policy.evaluate(&banner(SshHost::Client, "2.0", "dropbear_2022")));
    assert!(deny_policy.evaluate(&banner(SshHost::Client, "2.0", "OpenSSH_8.9")));
    assert!(!deny_policy.evaluate(&banner(SshHost::Client, "2.0", "dropbear_2022")));
}

#[test]
fn server_software_allow_and_deny() {
    let allow_policy = SshPolicy {
        server_software: vec![ssh_match(r"OpenSSH_.*", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        server_software: vec![ssh_match(r"dropbear_.*", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(allow_policy.evaluate(&banner(SshHost::Server, "2.0", "OpenSSH_8.9")));
    assert!(!allow_policy.evaluate(&banner(SshHost::Server, "2.0", "dropbear_2022")));
    assert!(deny_policy.evaluate(&banner(SshHost::Server, "2.0", "OpenSSH_8.9")));
    assert!(!deny_policy.evaluate(&banner(SshHost::Server, "2.0", "dropbear_2022")));
}

#[test]
fn proto_version_allow_and_deny() {
    let allow_policy = SshPolicy {
        client_proto_version: vec![ssh_match(r"2\.0", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        client_proto_version: vec![ssh_match(r"1\..*", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(allow_policy.evaluate(&banner(SshHost::Client, "2.0", "OpenSSH")));
    assert!(!allow_policy.evaluate(&banner(SshHost::Client, "1.99", "OpenSSH")));
    assert!(deny_policy.evaluate(&banner(SshHost::Client, "2.0", "OpenSSH")));
    assert!(!deny_policy.evaluate(&banner(SshHost::Client, "1.99", "OpenSSH")));
}

#[test]
fn server_proto_version_allow_and_deny() {
    let allow_policy = SshPolicy {
        server_proto_version: vec![ssh_match(r"2\.0", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        server_proto_version: vec![ssh_match(r"1\..*", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(allow_policy.evaluate(&banner(SshHost::Server, "2.0", "OpenSSH")));
    assert!(!allow_policy.evaluate(&banner(SshHost::Server, "1.99", "OpenSSH")));
    assert!(deny_policy.evaluate(&banner(SshHost::Server, "2.0", "OpenSSH")));
    assert!(!deny_policy.evaluate(&banner(SshHost::Server, "1.99", "OpenSSH")));
}

#[test]
fn kex_allow_and_deny() {
    let negotiated = SshNegotiated {
        kex: Some("curve25519-sha256".into()),
        ..Default::default()
    };
    let allow_policy = SshPolicy {
        kex: vec![ssh_match("curve25519-sha256", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        kex: vec![ssh_match("diffie-hellman-group1-sha1", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(allow_policy.evaluate(&negotiated));
    assert!(deny_policy.evaluate(&negotiated));

    let weak = SshNegotiated {
        kex: Some("diffie-hellman-group1-sha1".into()),
        ..Default::default()
    };
    assert!(!deny_policy.evaluate(&weak));
}

#[test]
fn host_key_alg_allow_and_deny() {
    let negotiated = SshNegotiated {
        host_key_alg: Some("ssh-ed25519".into()),
        ..Default::default()
    };
    let allow_policy = SshPolicy {
        host_key_alg: vec![ssh_match("ssh-ed25519", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        host_key_alg: vec![ssh_match("ssh-dss", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(allow_policy.evaluate(&negotiated));
    assert!(deny_policy.evaluate(&negotiated));
    assert!(!deny_policy.evaluate(&SshNegotiated {
        host_key_alg: Some("ssh-dss".into()),
        ..Default::default()
    }));
}

#[test]
fn cipher_allow_and_deny() {
    let negotiated = SshNegotiated {
        cipher_c2s: Some("chacha20-poly1305@openssh.com".into()),
        cipher_s2c: Some("chacha20-poly1305@openssh.com".into()),
        ..Default::default()
    };
    let allow_policy = SshPolicy {
        cipher: vec![ssh_match(r"chacha20-poly1305@openssh\.com", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        cipher: vec![ssh_match("3des-cbc", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(allow_policy.evaluate(&negotiated));
    assert!(deny_policy.evaluate(&negotiated));
    assert!(!deny_policy.evaluate(&SshNegotiated {
        cipher_c2s: Some("aes256-ctr".into()),
        cipher_s2c: Some("3des-cbc".into()),
        ..Default::default()
    }));
}

#[test]
fn mac_allow_and_deny() {
    let negotiated = SshNegotiated {
        mac_c2s: Some("hmac-sha2-256".into()),
        mac_s2c: Some("hmac-sha2-256".into()),
        ..Default::default()
    };
    let allow_policy = SshPolicy {
        mac: vec![ssh_match(r"hmac-sha2-256.*", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        mac: vec![ssh_match(r"hmac-md5.*", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(allow_policy.evaluate(&negotiated));
    assert!(deny_policy.evaluate(&negotiated));
    assert!(!deny_policy.evaluate(&SshNegotiated {
        mac_s2c: Some("hmac-md5".into()),
        ..Default::default()
    }));
}

#[test]
fn compression_allow_and_deny() {
    let negotiated = SshNegotiated {
        comp_c2s: Some("none".into()),
        comp_s2c: Some("none".into()),
        ..Default::default()
    };
    let allow_policy = SshPolicy {
        compression: vec![ssh_match("none", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        compression: vec![ssh_match(r"zlib.*", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(allow_policy.evaluate(&negotiated));
    assert!(deny_policy.evaluate(&negotiated));
    assert!(!deny_policy.evaluate(&SshNegotiated {
        comp_s2c: Some("zlib@openssh.com".into()),
        ..Default::default()
    }));
}

#[test]
fn host_key_type_allow_and_deny() {
    let info = SshHostKeyInfo {
        key_type: b"ssh-ed25519".to_vec(),
    };
    let allow_policy = SshPolicy {
        host_key_type: vec![ssh_match("ssh-ed25519", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        host_key_type: vec![ssh_match("ssh-rsa", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(allow_policy.evaluate(&info));
    assert!(deny_policy.evaluate(&info));
    assert!(!deny_policy.evaluate(&SshHostKeyInfo {
        key_type: b"ssh-rsa".to_vec(),
    }));
}

#[test]
fn disconnect_reason_allow_and_deny() {
    let info = SshDisconnectInfo { reason_code: 3 };
    let allow_policy = SshPolicy {
        disconnect_reason: vec![reason_match(&[1, 2], SshMatchAction::Allow)],
        ..SshPolicy::default()
    };
    let deny_policy = SshPolicy {
        disconnect_reason: vec![reason_match(&[3], SshMatchAction::Deny)],
        ..SshPolicy::default()
    };

    assert!(!allow_policy.evaluate(&info));
    assert!(!deny_policy.evaluate(&info));
    assert!(deny_policy.evaluate(&SshDisconnectInfo { reason_code: 1 }));
}

#[test]
fn negotiation_picks_client_preferred_mutual_entry() {
    let client = OwnedKexInit {
        kex_algs: vec!["A".into(), "B".into(), "C".into()],
        server_host_key_algs: vec![],
        encr_algs_client_to_server: vec![],
        encr_algs_server_to_client: vec![],
        mac_algs_client_to_server: vec![],
        mac_algs_server_to_client: vec![],
        comp_algs_client_to_server: vec![],
        comp_algs_server_to_client: vec![],
    };
    let server = OwnedKexInit {
        kex_algs: vec!["C".into(), "B".into()],
        ..client.clone()
    };

    let negotiated = compute_negotiated(&client, &server);
    assert_eq!(negotiated.kex.as_deref(), Some("B"));
}

#[test]
fn no_overlap_negotiated_none_passes_constrained_field() {
    let client = OwnedKexInit {
        kex_algs: vec!["A".into()],
        server_host_key_algs: vec![],
        encr_algs_client_to_server: vec![],
        encr_algs_server_to_client: vec![],
        mac_algs_client_to_server: vec![],
        mac_algs_server_to_client: vec![],
        comp_algs_client_to_server: vec![],
        comp_algs_server_to_client: vec![],
    };
    let server = OwnedKexInit {
        kex_algs: vec!["B".into()],
        ..client.clone()
    };
    let negotiated = compute_negotiated(&client, &server);
    assert!(negotiated.kex.is_none());

    let deny_policy = SshPolicy {
        kex: vec![ssh_match("A", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };
    assert!(deny_policy.evaluate(&negotiated));
}

#[test]
fn cipher_direction_asymmetry_denies_on_either_direction() {
    let negotiated = SshNegotiated {
        cipher_c2s: Some("aes256-ctr".into()),
        cipher_s2c: Some("3des-cbc".into()),
        ..Default::default()
    };
    let policy = SshPolicy {
        cipher: vec![ssh_match("3des-cbc", SshMatchAction::Deny)],
        ..SshPolicy::default()
    };
    assert!(!policy.evaluate(&negotiated));

    let clean_s2c = SshNegotiated {
        cipher_c2s: Some("3des-cbc".into()),
        cipher_s2c: Some("aes256-ctr".into()),
        ..Default::default()
    };
    assert!(!policy.evaluate(&clean_s2c));
}

#[test]
fn mixed_fields_all_must_satisfy() {
    let policy = SshPolicy {
        server_software: vec![ssh_match(r"OpenSSH_.*", SshMatchAction::Allow)],
        kex: vec![ssh_match("curve25519-sha256", SshMatchAction::Allow)],
        cipher: vec![ssh_match("aes256-ctr", SshMatchAction::Allow)],
        ..SshPolicy::default()
    };

    let banner_ok = banner(SshHost::Server, "2.0", "OpenSSH_9.6");
    let negotiated_ok = SshNegotiated {
        kex: Some("curve25519-sha256".into()),
        cipher_c2s: Some("aes256-ctr".into()),
        cipher_s2c: Some("aes256-ctr".into()),
        ..Default::default()
    };

    assert!(policy.evaluate(&banner_ok));
    assert!(policy.evaluate(&negotiated_ok));
    assert!(!policy.evaluate(&SshNegotiated {
        kex: Some("diffie-hellman-group1-sha1".into()),
        cipher_c2s: Some("aes256-ctr".into()),
        cipher_s2c: Some("aes256-ctr".into()),
        ..Default::default()
    }));
}

#[test]
fn deny_wins_over_allow_in_same_field() {
    let policy = SshPolicy {
        cipher: vec![
            ssh_match(".*", SshMatchAction::Allow),
            ssh_match("3des-cbc", SshMatchAction::Deny),
        ],
        ..SshPolicy::default()
    };
    assert!(!policy.evaluate(&SshNegotiated {
        cipher_c2s: Some("3des-cbc".into()),
        cipher_s2c: Some("aes256-ctr".into()),
        ..Default::default()
    }));
    assert!(policy.evaluate(&SshNegotiated {
        cipher_c2s: Some("aes256-ctr".into()),
        cipher_s2c: Some("aes256-ctr".into()),
        ..Default::default()
    }));
}

#[test]
fn allow_all_patterns_must_match() {
    let policy = SshPolicy {
        client_software: vec![
            ssh_match(r"OpenSSH.*", SshMatchAction::Allow),
            ssh_match(r".*8\.9", SshMatchAction::Allow),
        ],
        ..SshPolicy::default()
    };
    assert!(policy.evaluate(&banner(SshHost::Client, "2.0", "OpenSSH_8.9")));
    assert!(!policy.evaluate(&banner(SshHost::Client, "2.0", "OpenSSH_9.0")));
}

#[test]
fn multiple_policies_all_must_allow() {
    let policies = vec![
        SshPolicy {
            kex: vec![ssh_match("curve25519-sha256", SshMatchAction::Allow)],
            ..SshPolicy::default()
        },
        SshPolicy {
            cipher: vec![ssh_match("aes256-ctr", SshMatchAction::Allow)],
            ..SshPolicy::default()
        },
    ];
    let negotiated = SshNegotiated {
        kex: Some("curve25519-sha256".into()),
        cipher_c2s: Some("aes256-ctr".into()),
        cipher_s2c: Some("aes256-ctr".into()),
        ..Default::default()
    };
    assert!(SshPolicy::evaluate_policies(&policies, &negotiated));

    let denying = vec![
        policies[0].clone(),
        SshPolicy {
            cipher: vec![ssh_match("aes256-ctr", SshMatchAction::Deny)],
            ..SshPolicy::default()
        },
    ];
    assert!(!SshPolicy::evaluate_policies(&denying, &negotiated));
}

#[test]
fn empty_policy_set_denies() {
    let negotiated = SshNegotiated {
        kex: Some("curve25519-sha256".into()),
        ..Default::default()
    };
    assert!(!SshPolicy::evaluate_policies(&[], &negotiated));
}

#[test]
fn permissive_policy_allows_all_metadata() {
    let policy = permissive_policy();
    assert!(policy.evaluate(&banner(SshHost::Client, "2.0", "anything")));
    assert!(policy.evaluate(&SshNegotiated {
        kex: Some("weak".into()),
        cipher_s2c: Some("3des-cbc".into()),
        ..Default::default()
    }));
    assert!(policy.evaluate(&SshHostKeyInfo {
        key_type: b"ssh-rsa".to_vec(),
    }));
}

#[test]
fn policy_serde_roundtrip_ssh_fields() {
    let policy = Policy {
        name: "SSH policy roundtrip".to_string(),
        zone_pair_id: ZonePairId::from(
            Uuid::parse_str("60a19f28-39de-493a-a5f2-e47301149e36").unwrap(),
        ),
        priority: 10,
        rule_tree: RuleTree::new(
            parse_rule_tree("match protocol { = tcp : verdict allow }").unwrap(),
        ),
        smtp_policy: ngfw::policy::SmtpPolicy::default(),
        ssh_policy: SshPolicy {
            client_software: vec![ssh_match(r"OpenSSH_.*", SshMatchAction::Allow)],
            disconnect_reason: vec![reason_match(&[3], SshMatchAction::Deny)],
            ..SshPolicy::default()
        },
    };

    let serialized = serde_json::to_string(&policy).unwrap();
    let roundtrip: Policy = serde_json::from_str(&serialized).unwrap();

    assert_eq!(policy.name, roundtrip.name);
    assert_eq!(
        policy.ssh_policy.client_software[0].regex.as_str(),
        roundtrip.ssh_policy.client_software[0].regex.as_str()
    );
    assert_eq!(
        policy.ssh_policy.disconnect_reason[0].codes,
        roundtrip.ssh_policy.disconnect_reason[0].codes
    );
}

#[test]
fn policy_proto_roundtrip_ssh_matchers() {
    let policy = Policy {
        name: "SSH matchers".to_string(),
        zone_pair_id: ZonePairId::from(
            Uuid::parse_str("60a19f28-39de-493a-a5f2-e47301149e36").unwrap(),
        ),
        priority: 10,
        rule_tree: RuleTree::new(
            parse_rule_tree("match protocol { = tcp : verdict allow }").unwrap(),
        ),
        smtp_policy: ngfw::policy::SmtpPolicy::default(),
        ssh_policy: SshPolicy {
            kex: vec![ssh_match("curve25519-sha256", SshMatchAction::Allow)],
            disconnect_reason: vec![reason_match(&[3], SshMatchAction::Deny)],
            ..SshPolicy::default()
        },
    };

    let id = PolicyId::from(Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap());
    let rule = policy.into_rule(id);
    let (_, roundtrip) = Policy::try_from_rule(rule).unwrap();
    assert_eq!(
        policy.ssh_policy.kex[0].regex.as_str(),
        roundtrip.ssh_policy.kex[0].regex.as_str()
    );
    assert_eq!(
        policy.ssh_policy.disconnect_reason[0].codes,
        roundtrip.ssh_policy.disconnect_reason[0].codes
    );
}
