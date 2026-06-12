use crate::policy::{SshMatch, SshMatchAction, SshPolicy, SshReasonMatch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshHost {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshBannerInfo {
    pub host: SshHost,
    pub proto_version: Vec<u8>,
    pub software: Vec<u8>,
    pub comments: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshNegotiated {
    pub kex: Option<String>,
    pub host_key_alg: Option<String>,
    pub cipher_c2s: Option<String>,
    pub cipher_s2c: Option<String>,
    pub mac_c2s: Option<String>,
    pub mac_s2c: Option<String>,
    pub comp_c2s: Option<String>,
    pub comp_s2c: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshHostKeyInfo {
    pub key_type: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshDisconnectInfo {
    pub reason_code: u32,
}

pub trait SshMetadata {
    fn evaluate_against(&self, policy: &SshPolicy) -> bool;
}

impl SshPolicy {
    pub fn evaluate(&self, meta: &impl SshMetadata) -> bool {
        meta.evaluate_against(self)
    }

    pub fn evaluate_policies(policies: &[SshPolicy], meta: &impl SshMetadata) -> bool {
        if policies.is_empty() {
            return false;
        }
        policies.iter().all(|policy| policy.evaluate(meta))
    }
}

impl SshMetadata for SshBannerInfo {
    fn evaluate_against(&self, policy: &SshPolicy) -> bool {
        let (proto_matches, software_matches) = match self.host {
            SshHost::Client => (&policy.client_proto_version, &policy.client_software),
            SshHost::Server => (&policy.server_proto_version, &policy.server_software),
        };
        evaluate_field(proto_matches, &self.proto_version)
            && evaluate_field(software_matches, &self.software)
    }
}

impl SshMetadata for SshNegotiated {
    fn evaluate_against(&self, policy: &SshPolicy) -> bool {
        evaluate_optional_field(&policy.kex, self.kex.as_deref())
            && evaluate_optional_field(&policy.host_key_alg, self.host_key_alg.as_deref())
            && evaluate_optional_field(&policy.cipher, self.cipher_c2s.as_deref())
            && evaluate_optional_field(&policy.cipher, self.cipher_s2c.as_deref())
            && evaluate_optional_field(&policy.mac, self.mac_c2s.as_deref())
            && evaluate_optional_field(&policy.mac, self.mac_s2c.as_deref())
            && evaluate_optional_field(&policy.compression, self.comp_c2s.as_deref())
            && evaluate_optional_field(&policy.compression, self.comp_s2c.as_deref())
    }
}

impl SshMetadata for SshHostKeyInfo {
    fn evaluate_against(&self, policy: &SshPolicy) -> bool {
        evaluate_field(&policy.host_key_type, &self.key_type)
    }
}

impl SshMetadata for SshDisconnectInfo {
    fn evaluate_against(&self, policy: &SshPolicy) -> bool {
        evaluate_reason_field(&policy.disconnect_reason, self.reason_code)
    }
}

pub fn evaluate_field(matches: &[SshMatch], input: &[u8]) -> bool {
    if matches.is_empty() {
        return true;
    }

    let mut has_allow = false;
    let mut allow_matched = true;

    for matcher in matches {
        match matcher.on_match {
            SshMatchAction::Allow => {
                has_allow = true;
                allow_matched &= matcher.regex.is_match(input);
            }
            SshMatchAction::Deny => {
                if matcher.regex.is_match(input) {
                    return false;
                }
            }
        }
    }

    !has_allow || allow_matched
}

fn evaluate_optional_field(matches: &[SshMatch], value: Option<&str>) -> bool {
    match value {
        Some(v) => evaluate_field(matches, v.as_bytes()),
        None => true,
    }
}

pub fn evaluate_reason_field(matches: &[SshReasonMatch], code: u32) -> bool {
    if matches.is_empty() {
        return true;
    }

    let mut has_allow = false;
    let mut allow_matched = true;

    for matcher in matches {
        let code_matches = matcher.codes.contains(&code);
        match matcher.on_match {
            SshMatchAction::Allow => {
                has_allow = true;
                allow_matched &= code_matches;
            }
            SshMatchAction::Deny => {
                if code_matches {
                    return false;
                }
            }
        }
    }

    !has_allow || allow_matched
}

pub fn negotiate(client_list: &[String], server_list: &[String]) -> Option<String> {
    for alg in client_list {
        if server_list.contains(alg) {
            return Some(alg.clone());
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedKexInit {
    pub kex_algs: Vec<String>,
    pub server_host_key_algs: Vec<String>,
    pub encr_algs_client_to_server: Vec<String>,
    pub encr_algs_server_to_client: Vec<String>,
    pub mac_algs_client_to_server: Vec<String>,
    pub mac_algs_server_to_client: Vec<String>,
    pub comp_algs_client_to_server: Vec<String>,
    pub comp_algs_server_to_client: Vec<String>,
}

impl OwnedKexInit {
    pub fn from_kexinit(kex: &ssh_parser::SshPacketKeyExchange<'_>) -> Self {
        let names = |get: Result<Vec<&str>, _>| {
            get.ok()
                .map(|algs| algs.into_iter().map(str::to_owned).collect())
                .unwrap_or_default()
        };
        Self {
            kex_algs: names(kex.get_kex_algs()),
            server_host_key_algs: names(kex.get_server_host_key_algs()),
            encr_algs_client_to_server: names(kex.get_encr_algs_client_to_server()),
            encr_algs_server_to_client: names(kex.get_encr_algs_server_to_client()),
            mac_algs_client_to_server: names(kex.get_mac_algs_client_to_server()),
            mac_algs_server_to_client: names(kex.get_mac_algs_server_to_client()),
            comp_algs_client_to_server: names(kex.get_comp_algs_client_to_server()),
            comp_algs_server_to_client: names(kex.get_comp_algs_server_to_client()),
        }
    }
}

pub fn compute_negotiated(client: &OwnedKexInit, server: &OwnedKexInit) -> SshNegotiated {
    SshNegotiated {
        kex: negotiate(&client.kex_algs, &server.kex_algs),
        host_key_alg: negotiate(&client.server_host_key_algs, &server.server_host_key_algs),
        cipher_c2s: negotiate(
            &client.encr_algs_client_to_server,
            &server.encr_algs_client_to_server,
        ),
        cipher_s2c: negotiate(
            &client.encr_algs_server_to_client,
            &server.encr_algs_server_to_client,
        ),
        mac_c2s: negotiate(&client.mac_algs_client_to_server, &server.mac_algs_client_to_server),
        mac_s2c: negotiate(&client.mac_algs_server_to_client, &server.mac_algs_server_to_client),
        comp_c2s: negotiate(
            &client.comp_algs_client_to_server,
            &server.comp_algs_client_to_server,
        ),
        comp_s2c: negotiate(
            &client.comp_algs_server_to_client,
            &server.comp_algs_server_to_client,
        ),
    }
}

pub fn first_ssh_string(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes(data[..4].try_into().ok()?) as usize;
    if data.len() < 4 + len {
        return None;
    }
    Some(&data[4..4 + len])
}

#[cfg(test)]
mod tests {
    use regex::bytes::Regex;

    use super::*;

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
        let policy = SshPolicy::permissive();
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
}

impl Default for SshNegotiated {
    fn default() -> Self {
        Self {
            kex: None,
            host_key_alg: None,
            cipher_c2s: None,
            cipher_s2c: None,
            mac_c2s: None,
            mac_s2c: None,
            comp_c2s: None,
            comp_s2c: None,
        }
    }
}
