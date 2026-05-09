use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use etherparse::{PacketBuilder, SlicedPacket};
use ngfw::data_plane::tcp_session_tracker::{EndpointIdentifier, TcpIdentifier};
use ngfw::dpi::smtp::SmtpTracker;
use ngfw::dpi::smtp_policy_retriever::{SmtpPolicyRetriever, SmtpSessionPolicies};
use ngfw::policy::provider::DiskPolicyProvider;
use ngfw::policy::{Policy, PolicyId, SmtpPolicy, SmtpMatch, SmtpMatchAction};
use ngfw::rule_tree::{ArmEnd, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict};
use ngfw::zones::resolver::ZoneResolver;
use ngfw::zones::{DefaultPolicy, DirectionalZonePairs, ResolvedZonePair, ZonePairId};
use regex::bytes::Regex;
use uuid::Uuid;

struct MockZoneResolver {
    internal_zone_pair_id: ZonePairId,
    external_zone_pair_id: ZonePairId,
}

impl ZoneResolver for MockZoneResolver {
    fn resolve(&self, _: &str, _: IpAddr) -> Option<ResolvedZonePair> {
        None
    }

    fn resolve_bidirectional(&self, src_ip: IpAddr, _dst_ip: IpAddr) -> DirectionalZonePairs {
        let is_internal_src = matches!(src_ip, IpAddr::V4(ip) if ip.octets()[0] == 10);
        
        if is_internal_src {
            DirectionalZonePairs {
                forward: Some(ResolvedZonePair {
                    id: self.internal_zone_pair_id.clone(),
                    default_policy: DefaultPolicy::Drop,
                }),
                reverse: Some(ResolvedZonePair {
                    id: self.external_zone_pair_id.clone(),
                    default_policy: DefaultPolicy::Drop,
                }),
            }
        } else {
            DirectionalZonePairs {
                forward: Some(ResolvedZonePair {
                    id: self.external_zone_pair_id.clone(),
                    default_policy: DefaultPolicy::Drop,
                }),
                reverse: Some(ResolvedZonePair {
                    id: self.internal_zone_pair_id.clone(),
                    default_policy: DefaultPolicy::Drop,
                }),
            }
        }
    }
}

struct SmtpTestFixture {
    tracker: Arc<SmtpTracker<MockZoneResolver>>,
    internal_zone_pair_id: ZonePairId,
    external_zone_pair_id: ZonePairId,
}

fn internal_zone_pair_id() -> ZonePairId {
    Uuid::from_u128(1001).into()
}

fn external_zone_pair_id() -> ZonePairId {
    Uuid::from_u128(1002).into()
}

impl SmtpTestFixture {
    fn with_policies(policies: Vec<(ZonePairId, SmtpPolicy)>) -> Self {
        let internal_zone_pair_id = internal_zone_pair_id();
        let external_zone_pair_id = external_zone_pair_id();

        let zone_resolver = Arc::new(MockZoneResolver {
            internal_zone_pair_id: internal_zone_pair_id.clone(),
            external_zone_pair_id: external_zone_pair_id.clone(),
        });

        let mut policy_map = HashMap::new();
        for (i, (zone_pair_id, smtp_policy)) in policies.into_iter().enumerate() {
            let policy_id = PolicyId::from(Uuid::from_u128(2000 + i as u128));
            let policy = Policy {
                name: format!("test-policy-{}", i),
                zone_pair_id,
                priority: i as u32,
                rule_tree: RuleTree::new(
                    MatchBuilder::with_arm(
                        MatchKind::IpVer,
                        Pattern::Wildcard,
                        ArmEnd::Verdict(Verdict::Allow),
                    )
                    .build()
                    .unwrap(),
                ),
                smtp_policy,
            };
            policy_map.insert(policy_id, policy);
        }

        let policy_provider = Arc::new(DiskPolicyProvider::from_policies(
            policy_map,
            std::path::PathBuf::from("/tmp"),
        ));

        let smtp_policy_retriever = Arc::new(SmtpPolicyRetriever::new(
            zone_resolver,
            policy_provider,
        ));

        let tracker = Arc::new(SmtpTracker::new(smtp_policy_retriever));

        Self {
            tracker,
            internal_zone_pair_id,
            external_zone_pair_id,
        }
    }

    fn simulate_session(&self, client_ip: &str, server_ip: &str) -> TcpIdentifier {
        let client = EndpointIdentifier {
            ip: client_ip.parse().unwrap(),
            port: 54321u16.into(),
        };
        let server = EndpointIdentifier {
            ip: server_ip.parse().unwrap(),
            port: 25u16.into(),
        };

        let session_id = TcpIdentifier::new(client.clone(), server.clone());

        let packet = smtp_packet(&server, &client, b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        self.tracker.on_new_packet(sliced.transport.unwrap(), &session_id, server, client);

        session_id
    }

    fn get_policies(&self, session_id: &TcpIdentifier) -> SmtpSessionPolicies {
        self.tracker.get_session_policies(session_id).unwrap()
    }
}

fn smtp_packet(src: &EndpointIdentifier, dst: &EndpointIdentifier, payload: &[u8]) -> Vec<u8> {
    let src_ip = match src.ip {
        IpAddr::V4(ip) => ip.octets(),
        _ => panic!("IPv6 not supported in tests"),
    };
    let dst_ip = match dst.ip {
        IpAddr::V4(ip) => ip.octets(),
        _ => panic!("IPv6 not supported in tests"),
    };

    let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4(src_ip, dst_ip, 64)
        .tcp(u16::from(src.port), u16::from(dst.port), 1000, 8192);

    let mut packet_data = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet_data, payload).unwrap();
    packet_data
}

#[test]
fn sender_filter_internal_to_external() {
    let mut policy = SmtpPolicy::default();
    policy.sender.push(SmtpMatch {
        regex: Regex::new(".*@gmail\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let fixture = SmtpTestFixture::with_policies(vec![(internal_zone_pair_id(), policy)]);

    let session = fixture.simulate_session("10.0.0.10", "192.168.1.100");
    let policies = fixture.get_policies(&session);

    assert_eq!(policies.client_to_server.len(), 1);
    assert!(policies.client_to_server[0].sender[0].regex.is_match(b"test@gmail.com"));
    assert!(!policies.client_to_server[0].sender[0].regex.is_match(b"test@yahoo.com"));
}

#[test]
fn recipient_filter_internal_to_external() {
    let mut policy = SmtpPolicy::default();
    policy.recipient.push(SmtpMatch {
        regex: Regex::new(".*@gmail\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let fixture = SmtpTestFixture::with_policies(vec![(internal_zone_pair_id(), policy)]);

    let session = fixture.simulate_session("10.0.0.10", "192.168.1.100");
    let policies = fixture.get_policies(&session);

    assert_eq!(policies.client_to_server.len(), 1);
    assert!(policies.client_to_server[0].recipient[0].regex.is_match(b"test@gmail.com"));
    assert!(!policies.client_to_server[0].recipient[0].regex.is_match(b"test@yahoo.com"));
}

#[test]
fn sender_and_recipient_filter_internal_to_external() {
    let mut policy = SmtpPolicy::default();
    policy.sender.push(SmtpMatch {
        regex: Regex::new(".*@gmail\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    policy.recipient.push(SmtpMatch {
        regex: Regex::new(".*@example\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let fixture = SmtpTestFixture::with_policies(vec![(internal_zone_pair_id(), policy)]);

    let session = fixture.simulate_session("10.0.0.10", "192.168.1.100");
    let policies = fixture.get_policies(&session);

    assert_eq!(policies.client_to_server.len(), 1);
    assert!(policies.client_to_server[0].sender[0].regex.is_match(b"test@gmail.com"));
    assert!(policies.client_to_server[0].recipient[0].regex.is_match(b"test@example.com"));
}

#[test]
fn sender_filter_external_to_internal() {
    let mut policy = SmtpPolicy::default();
    policy.sender.push(SmtpMatch {
        regex: Regex::new(".*@gmail\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let fixture = SmtpTestFixture::with_policies(vec![(external_zone_pair_id(), policy)]);

    let session = fixture.simulate_session("192.168.1.100", "10.0.0.10");
    let policies = fixture.get_policies(&session);

    assert_eq!(policies.client_to_server.len(), 1);
    assert!(policies.client_to_server[0].sender[0].regex.is_match(b"test@gmail.com"));
    assert!(!policies.client_to_server[0].sender[0].regex.is_match(b"test@yahoo.com"));
}

#[test]
fn recipient_filter_external_to_internal() {
    let mut policy = SmtpPolicy::default();
    policy.recipient.push(SmtpMatch {
        regex: Regex::new(".*@gmail\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let fixture = SmtpTestFixture::with_policies(vec![(external_zone_pair_id(), policy)]);

    let session = fixture.simulate_session("192.168.1.100", "10.0.0.10");
    let policies = fixture.get_policies(&session);

    assert_eq!(policies.client_to_server.len(), 1);
    assert!(policies.client_to_server[0].recipient[0].regex.is_match(b"test@gmail.com"));
    assert!(!policies.client_to_server[0].recipient[0].regex.is_match(b"test@yahoo.com"));
}

#[test]
fn sender_and_recipient_filter_external_to_internal() {
    let mut policy = SmtpPolicy::default();
    policy.sender.push(SmtpMatch {
        regex: Regex::new(".*@gmail\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    policy.recipient.push(SmtpMatch {
        regex: Regex::new(".*@example\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let fixture = SmtpTestFixture::with_policies(vec![(external_zone_pair_id(), policy)]);

    let session = fixture.simulate_session("192.168.1.100", "10.0.0.10");
    let policies = fixture.get_policies(&session);

    assert_eq!(policies.client_to_server.len(), 1);
    assert!(policies.client_to_server[0].sender[0].regex.is_match(b"test@gmail.com"));
    assert!(policies.client_to_server[0].recipient[0].regex.is_match(b"test@example.com"));
}

#[test]
fn message_filter_internal_to_external() {
    let mut policy = SmtpPolicy::default();
    policy.message.push(SmtpMatch {
        regex: Regex::new(".*Hello.*").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let fixture = SmtpTestFixture::with_policies(vec![(internal_zone_pair_id(), policy)]);

    let session = fixture.simulate_session("10.0.0.10", "192.168.1.100");
    let policies = fixture.get_policies(&session);

    assert_eq!(policies.client_to_server.len(), 1);
    assert!(policies.client_to_server[0].message[0].regex.is_match(b"Hello world"));
    assert!(!policies.client_to_server[0].message[0].regex.is_match(b"Goodbye"));
}

#[test]
fn message_filter_external_to_internal() {
    let mut policy = SmtpPolicy::default();
    policy.message.push(SmtpMatch {
        regex: Regex::new(".*Hello.*").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let fixture = SmtpTestFixture::with_policies(vec![(external_zone_pair_id(), policy)]);

    let session = fixture.simulate_session("192.168.1.100", "10.0.0.10");
    let policies = fixture.get_policies(&session);

    assert_eq!(policies.client_to_server.len(), 1);
    assert!(policies.client_to_server[0].message[0].regex.is_match(b"Hello world"));
    assert!(!policies.client_to_server[0].message[0].regex.is_match(b"Goodbye"));
}

#[test]
fn multiple_policies_same_zone_pair() {
    let mut policy1 = SmtpPolicy::default();
    policy1.sender.push(SmtpMatch {
        regex: Regex::new(".*@gmail\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let mut policy2 = SmtpPolicy::default();
    policy2.sender.push(SmtpMatch {
        regex: Regex::new(".*@yahoo\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let fixture = SmtpTestFixture::with_policies(vec![
        (internal_zone_pair_id(), policy1),
        (internal_zone_pair_id(), policy2),
    ]);

    let session = fixture.simulate_session("10.0.0.10", "192.168.1.100");
    let policies = fixture.get_policies(&session);

    assert_eq!(policies.client_to_server.len(), 2);
    let has_gmail = policies.client_to_server.iter().any(|p| p.sender.iter().any(|m| m.regex.is_match(b"test@gmail.com")));
    let has_yahoo = policies.client_to_server.iter().any(|p| p.sender.iter().any(|m| m.regex.is_match(b"test@yahoo.com")));
    assert!(has_gmail);
    assert!(has_yahoo);
}

#[test]
fn different_rules_per_zone_pair() {
    let mut policy1 = SmtpPolicy::default();
    policy1.recipient.push(SmtpMatch {
        regex: Regex::new(".*@gmail\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });
    
    let mut policy2 = SmtpPolicy::default();
    policy2.recipient.push(SmtpMatch {
        regex: Regex::new(".*@yahoo\\.com").unwrap(),
        on_match: SmtpMatchAction::Allow,
    });

    let fixture = SmtpTestFixture::with_policies(vec![
        (internal_zone_pair_id(), policy1),
        (external_zone_pair_id(), policy2),
    ]);

    let session1 = fixture.simulate_session("10.0.0.10", "192.168.1.100");
    let policies1 = fixture.get_policies(&session1);
    assert_eq!(policies1.client_to_server.len(), 1);
    assert!(policies1.client_to_server[0].recipient[0].regex.is_match(b"test@gmail.com"));
    assert!(!policies1.client_to_server[0].recipient[0].regex.is_match(b"test@yahoo.com"));

    let session2 = fixture.simulate_session("192.168.1.100", "10.0.0.10");
    let policies2 = fixture.get_policies(&session2);
    assert_eq!(policies2.client_to_server.len(), 1);
    assert!(policies2.client_to_server[0].recipient[0].regex.is_match(b"test@yahoo.com"));
    assert!(!policies2.client_to_server[0].recipient[0].regex.is_match(b"test@gmail.com"));
}
