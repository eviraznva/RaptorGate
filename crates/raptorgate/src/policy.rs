use derive_more::{Display, From, Into};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{proto::config::Rule, rule_tree::RuleTree, zones::ZonePairId};
pub use crate::rule_tree::parsing::{RaptorlangError, parse_rule_tree};

pub mod engine;
pub mod policy_evaluator;
pub mod provider;
pub mod retriever;

// tonic::include_proto!("raptorgate.config");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    // #[serde(skip_serializing)] //TODO: this is bad, ideally this shouldn't have an id at all and the id should only be used for correlation
    // pub id: PolicyId,

    pub name: String,
    // pub description: Option<String>,
    pub zone_pair_id: ZonePairId,
    // pub is_active: bool,
    pub priority: u32,
    // pub created_at: SystemTime,
    // pub updated_at: SystemTime,
    // pub created_by: String,

    pub rule_tree: RuleTree,

    pub smtp_policy: SmtpPolicy,
    pub ssh_policy: SshPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmtpMatchAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpMatch {
    #[serde(with = "serde_regex")]
    pub regex: Regex,
    pub on_match: SmtpMatchAction,
}

mod serde_regex {
    use regex::bytes::Regex;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(regex: &Regex, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        regex.as_str().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Regex, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Regex::new(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpPolicy {
    pub sender: Vec<SmtpMatch>,
    pub recipient: Vec<SmtpMatch>,
    pub message: Vec<SmtpMatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SshMatchAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshMatch {
    #[serde(with = "serde_regex")]
    pub regex: Regex,
    pub on_match: SshMatchAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshReasonMatch {
    pub codes: Vec<u32>,
    pub on_match: SshMatchAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshPolicy {
    pub client_software: Vec<SshMatch>,
    pub server_software: Vec<SshMatch>,
    pub client_proto_version: Vec<SshMatch>,
    pub server_proto_version: Vec<SshMatch>,
    pub kex: Vec<SshMatch>,
    pub host_key_alg: Vec<SshMatch>,
    pub cipher: Vec<SshMatch>,
    pub mac: Vec<SshMatch>,
    pub compression: Vec<SshMatch>,
    pub host_key_type: Vec<SshMatch>,
    pub disconnect_reason: Vec<SshReasonMatch>,
}

impl SshPolicy {
    pub fn default() -> Self {
        Self {
            client_software: vec![],
            server_software: vec![],
            client_proto_version: vec![],
            server_proto_version: vec![],
            kex: vec![],
            host_key_alg: vec![],
            cipher: vec![],
            mac: vec![],
            compression: vec![],
            host_key_type: vec![],
            disconnect_reason: vec![],
        }
    }

    #[cfg(test)]
    pub fn permissive() -> Self {
        let allow_all = SshMatch {
            regex: Regex::new(".*").unwrap(),
            on_match: SshMatchAction::Allow,
        };
        Self {
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
}

impl SmtpPolicy {
    pub fn default() -> Self {
        Self {
            sender: vec![],
            recipient: vec![],
            message: vec![],
        }
    }

    #[cfg(test)]
    pub fn permissive() -> Self {
        Self {
            sender: vec![SmtpMatch {
                regex: Regex::new(".*").unwrap(),
                on_match: SmtpMatchAction::Allow,
            }],
            recipient: vec![SmtpMatch {
                regex: Regex::new(".*").unwrap(),
                on_match: SmtpMatchAction::Allow,
            }],
            message: vec![SmtpMatch {
                regex: Regex::new(".*").unwrap(),
                on_match: SmtpMatchAction::Allow,
            }],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, From, Into, Deserialize, Serialize, Display)]
pub struct PolicyId(Uuid);

impl Policy {
    pub fn try_from_rule(value: Rule) -> Result<(PolicyId, Self), anyhow::Error> {
        let head = parse_rule_tree(&value.content)?;
        
        let smtp_policy = if let Some(matchers) = value.smtp_matchers {
            use crate::proto::config::SmtpMatchAction as ProtoAction;
            
            let parse_match_list = |list: Vec<crate::proto::config::SmtpMatch>, field_name: &str| -> Result<Vec<SmtpMatch>, anyhow::Error> {
                list.into_iter()
                    .map(|m| {
                        let action = match ProtoAction::try_from(m.on_match) {
                            Ok(ProtoAction::Allow) => crate::policy::SmtpMatchAction::Allow,
                            Ok(ProtoAction::Deny) => crate::policy::SmtpMatchAction::Deny,
                            _ => return Err(anyhow::anyhow!("Invalid {} action: must be ALLOW or DENY", field_name)),
                        };
                        let regex = Regex::new(&m.regex)
                            .map_err(|e| anyhow::anyhow!("Invalid {} regex: {}", field_name, e))?;
                        Ok(SmtpMatch { regex, on_match: action })
                    })
                    .collect()
            };

            SmtpPolicy {
                sender: parse_match_list(matchers.sender, "smtp_sender")?,
                recipient: parse_match_list(matchers.recipient, "smtp_recipient")?,
                message: parse_match_list(matchers.message, "smtp_message")?,
            }
        } else {
            SmtpPolicy::default()
        };

        let ssh_policy = if let Some(matchers) = value.ssh_matchers {
            use crate::proto::config::SshMatchAction as ProtoAction;

            let parse_ssh_match_list =
                |list: Vec<crate::proto::config::SshMatch>, field_name: &str| -> Result<Vec<SshMatch>, anyhow::Error> {
                    list.into_iter()
                        .map(|m| {
                            let action = match ProtoAction::try_from(m.on_match) {
                                Ok(ProtoAction::Allow) => SshMatchAction::Allow,
                                Ok(ProtoAction::Deny) => SshMatchAction::Deny,
                                _ => {
                                    return Err(anyhow::anyhow!(
                                        "Invalid {} action: must be ALLOW or DENY",
                                        field_name
                                    ));
                                }
                            };
                            let regex = Regex::new(&m.regex)
                                .map_err(|e| anyhow::anyhow!("Invalid {} regex: {}", field_name, e))?;
                            Ok(SshMatch { regex, on_match: action })
                        })
                        .collect()
                };

            let parse_reason_list = |list: Vec<crate::proto::config::SshReasonMatch>,
                                     field_name: &str|
             -> Result<Vec<SshReasonMatch>, anyhow::Error> {
                list.into_iter()
                    .map(|m| {
                        let action = match ProtoAction::try_from(m.on_match) {
                            Ok(ProtoAction::Allow) => SshMatchAction::Allow,
                            Ok(ProtoAction::Deny) => SshMatchAction::Deny,
                            _ => {
                                return Err(anyhow::anyhow!(
                                    "Invalid {} action: must be ALLOW or DENY",
                                    field_name
                                ));
                            }
                        };
                        Ok(SshReasonMatch {
                            codes: m.codes,
                            on_match: action,
                        })
                    })
                    .collect()
            };

            SshPolicy {
                client_software: parse_ssh_match_list(matchers.client_software, "ssh_client_software")?,
                server_software: parse_ssh_match_list(matchers.server_software, "ssh_server_software")?,
                client_proto_version: parse_ssh_match_list(matchers.client_proto_version, "ssh_client_proto_version")?,
                server_proto_version: parse_ssh_match_list(matchers.server_proto_version, "ssh_server_proto_version")?,
                kex: parse_ssh_match_list(matchers.kex, "ssh_kex")?,
                host_key_alg: parse_ssh_match_list(matchers.host_key_alg, "ssh_host_key_alg")?,
                cipher: parse_ssh_match_list(matchers.cipher, "ssh_cipher")?,
                mac: parse_ssh_match_list(matchers.mac, "ssh_mac")?,
                compression: parse_ssh_match_list(matchers.compression, "ssh_compression")?,
                host_key_type: parse_ssh_match_list(matchers.host_key_type, "ssh_host_key_type")?,
                disconnect_reason: parse_reason_list(matchers.disconnect_reason, "ssh_disconnect_reason")?,
            }
        } else {
            SshPolicy::default()
        };
        
        Ok((PolicyId(value.id.try_into()?),
        Policy {
            name: value.name.clone(),
            zone_pair_id: ZonePairId::from(Uuid::parse_str(&value.zone_pair_id)?),
            priority: value.priority,
            rule_tree: RuleTree::new(head),
            smtp_policy,
            ssh_policy,
        }))
    }

    pub fn into_rule(&self, id: PolicyId) -> Rule {
        use crate::proto::config::SmtpMatchAction as ProtoAction;

        let to_proto_match = |m: &SmtpMatch| -> crate::proto::config::SmtpMatch {
            crate::proto::config::SmtpMatch {
                regex: m.regex.as_str().to_string(),
                on_match: match m.on_match {
                    crate::policy::SmtpMatchAction::Allow => ProtoAction::Allow as i32,
                    crate::policy::SmtpMatchAction::Deny => ProtoAction::Deny as i32,
                },
            }
        };

        let smtp_matchers = Some(crate::proto::config::SmtpMatchers {
            sender: self.smtp_policy.sender.iter().map(to_proto_match).collect(),
            recipient: self.smtp_policy.recipient.iter().map(to_proto_match).collect(),
            message: self.smtp_policy.message.iter().map(to_proto_match).collect(),
        });

        let to_proto_ssh_match = |m: &SshMatch| -> crate::proto::config::SshMatch {
            crate::proto::config::SshMatch {
                regex: m.regex.as_str().to_string(),
                on_match: match m.on_match {
                    SshMatchAction::Allow => crate::proto::config::SshMatchAction::Allow as i32,
                    SshMatchAction::Deny => crate::proto::config::SshMatchAction::Deny as i32,
                },
            }
        };

        let ssh_matchers = Some(crate::proto::config::SshMatchers {
            client_software: self.ssh_policy.client_software.iter().map(to_proto_ssh_match).collect(),
            server_software: self.ssh_policy.server_software.iter().map(to_proto_ssh_match).collect(),
            client_proto_version: self.ssh_policy.client_proto_version.iter().map(to_proto_ssh_match).collect(),
            server_proto_version: self.ssh_policy.server_proto_version.iter().map(to_proto_ssh_match).collect(),
            kex: self.ssh_policy.kex.iter().map(to_proto_ssh_match).collect(),
            host_key_alg: self.ssh_policy.host_key_alg.iter().map(to_proto_ssh_match).collect(),
            cipher: self.ssh_policy.cipher.iter().map(to_proto_ssh_match).collect(),
            mac: self.ssh_policy.mac.iter().map(to_proto_ssh_match).collect(),
            compression: self.ssh_policy.compression.iter().map(to_proto_ssh_match).collect(),
            host_key_type: self.ssh_policy.host_key_type.iter().map(to_proto_ssh_match).collect(),
            disconnect_reason: self
                .ssh_policy
                .disconnect_reason
                .iter()
                .map(|m| crate::proto::config::SshReasonMatch {
                    codes: m.codes.clone(),
                    on_match: match m.on_match {
                        SshMatchAction::Allow => crate::proto::config::SshMatchAction::Allow as i32,
                        SshMatchAction::Deny => crate::proto::config::SshMatchAction::Deny as i32,
                    },
                })
                .collect(),
        });
        
        Rule {
            id: Uuid::from(id).into(),
            name: self.name.clone(),
            zone_pair_id: Uuid::from(self.zone_pair_id.clone()).into(),
            priority: self.priority,
            content: self.rule_tree.to_string(),
            smtp_matchers,
            ssh_matchers,
        }
    }
}

use crate::validation::foreign_keys;
foreign_keys!(Policy { zone_pair_id: ZonePairId });

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const EXPECTED_IDENTITY_RULES: [&str; 4] = [
        "Identity pre-auth portal gate",
        "Identity guest sensitive deny",
        "Identity admin management access",
        "Identity authenticated app access",
    ];

    #[test]
    fn backend_identity_seed_rules_parse() {
        let raw = include_str!("../../../backend/data/json-db/rules.json");
        let parsed: serde_json::Value = serde_json::from_str(raw).unwrap();
        let items = parsed["items"].as_array().unwrap();
        let names = items
            .iter()
            .map(|item| item["name"].as_str().unwrap())
            .collect::<Vec<_>>();

        for expected in EXPECTED_IDENTITY_RULES {
            assert!(names.contains(&expected));
        }

        for item in items {
            parse_rule_tree(item["content"].as_str().unwrap()).unwrap();
        }
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = Policy {
            name: "Allow SMTP from trusted domains".to_string(),
            zone_pair_id: ZonePairId::from(Uuid::parse_str("60a19f28-39de-493a-a5f2-e47301149e36").unwrap()),
            priority: 10,
            rule_tree: RuleTree::new(parse_rule_tree("match protocol { = tcp : verdict allow }").unwrap()),
            smtp_policy: SmtpPolicy {
                sender: vec![SmtpMatch {
                    regex: Regex::new(r"^.*@trusted\\.com$").unwrap(),
                    on_match: SmtpMatchAction::Allow,
                }],
                recipient: vec![SmtpMatch {
                    regex: Regex::new(r"^ops@company\\.com$").unwrap(),
                    on_match: SmtpMatchAction::Deny,
                }],
                message: vec![SmtpMatch {
                    regex: Regex::new(r"^urgent:").unwrap(),
                    on_match: SmtpMatchAction::Allow,
                }],
            },
            ssh_policy: SshPolicy {
                client_software: vec![SshMatch {
                    regex: Regex::new(r"OpenSSH_.*").unwrap(),
                    on_match: SshMatchAction::Allow,
                }],
                disconnect_reason: vec![SshReasonMatch {
                    codes: vec![3],
                    on_match: SshMatchAction::Deny,
                }],
                ..SshPolicy::default()
            },
        };

        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.json");
        let serialized = serde_json::to_string_pretty(&policy).unwrap();
        fs::write(&path, serialized).unwrap();

        let loaded = fs::read_to_string(&path).unwrap();
        let roundtrip: Policy = serde_json::from_str(&loaded).unwrap();

        assert_eq!(policy.name, roundtrip.name);
        assert_eq!(policy.zone_pair_id, roundtrip.zone_pair_id);
        assert_eq!(policy.priority, roundtrip.priority);
        assert_eq!(policy.rule_tree.to_string(), roundtrip.rule_tree.to_string());

        let to_pairs = |items: &[SmtpMatch]| -> Vec<(String, SmtpMatchAction)> {
            items
                .iter()
                .map(|item| (item.regex.as_str().to_string(), item.on_match))
                .collect()
        };

        assert_eq!(to_pairs(&policy.smtp_policy.sender), to_pairs(&roundtrip.smtp_policy.sender));
        assert_eq!(to_pairs(&policy.smtp_policy.recipient), to_pairs(&roundtrip.smtp_policy.recipient));
        assert_eq!(to_pairs(&policy.smtp_policy.message), to_pairs(&roundtrip.smtp_policy.message));

        let ssh_to_pairs = |items: &[SshMatch]| -> Vec<(String, SshMatchAction)> {
            items
                .iter()
                .map(|item| (item.regex.as_str().to_string(), item.on_match))
                .collect()
        };
        assert_eq!(
            ssh_to_pairs(&policy.ssh_policy.client_software),
            ssh_to_pairs(&roundtrip.ssh_policy.client_software)
        );
        assert_eq!(
            policy.ssh_policy.disconnect_reason[0].codes,
            roundtrip.ssh_policy.disconnect_reason[0].codes
        );
    }

    #[test]
    fn policy_into_rule_keeps_empty_smtp_matchers_explicit() {
        let policy = Policy {
            name: "Empty SMTP".to_string(),
            zone_pair_id: ZonePairId::from(Uuid::parse_str("60a19f28-39de-493a-a5f2-e47301149e36").unwrap()),
            priority: 10,
            rule_tree: RuleTree::new(parse_rule_tree("match protocol { = tcp : verdict allow }").unwrap()),
            smtp_policy: SmtpPolicy::default(),
            ssh_policy: SshPolicy::default(),
        };

        let rule = policy.into_rule(Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap().into());

        assert!(rule.smtp_matchers.is_some());
        let smtp_matchers = rule.smtp_matchers.unwrap();
        assert!(smtp_matchers.sender.is_empty());
        assert!(smtp_matchers.recipient.is_empty());
        assert!(smtp_matchers.message.is_empty());

        assert!(rule.ssh_matchers.is_some());
        let ssh_matchers = rule.ssh_matchers.unwrap();
        assert!(ssh_matchers.client_software.is_empty());
        assert!(ssh_matchers.disconnect_reason.is_empty());
    }

    #[test]
    fn try_from_rule_ssh_deny_client_software() {
        use crate::dpi::ssh::policy::{SshBannerInfo, SshHost};
        use crate::proto::config::{SshMatch, SshMatchAction, SshMatchers};

        let rule = Rule {
            id: Uuid::parse_str("33333333-3333-4333-8333-333333333333")
                .unwrap()
                .into(),
            name: "ssh deny".to_string(),
            zone_pair_id: Uuid::parse_str("60a19f28-39de-493a-a5f2-e47301149e36")
                .unwrap()
                .into(),
            priority: 1,
            content: "match protocol { = tcp : verdict allow }".to_string(),
            smtp_matchers: None,
            ssh_matchers: Some(SshMatchers {
                client_software: vec![SshMatch {
                    regex: "OpenSSH_.*".to_string(),
                    on_match: SshMatchAction::Deny as i32,
                }],
                ..Default::default()
            }),
        };

        let (_, policy) = Policy::try_from_rule(rule).unwrap();
        let banner = SshBannerInfo {
            host: SshHost::Client,
            proto_version: b"2.0".to_vec(),
            software: b"OpenSSH_8.9".to_vec(),
            comments: None,
        };
        assert!(!policy.ssh_policy.evaluate(&banner));
    }

    #[test]
    fn policy_try_from_rule_roundtrips_ssh_matchers() {
        let policy = Policy {
            name: "SSH matchers".to_string(),
            zone_pair_id: ZonePairId::from(Uuid::parse_str("60a19f28-39de-493a-a5f2-e47301149e36").unwrap()),
            priority: 10,
            rule_tree: RuleTree::new(parse_rule_tree("match protocol { = tcp : verdict allow }").unwrap()),
            smtp_policy: SmtpPolicy::default(),
            ssh_policy: SshPolicy {
                kex: vec![SshMatch {
                    regex: Regex::new("curve25519-sha256").unwrap(),
                    on_match: SshMatchAction::Allow,
                }],
                ..SshPolicy::default()
            },
        };

        let id = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap().into();
        let rule = policy.into_rule(id);
        let (_, roundtrip) = Policy::try_from_rule(rule).unwrap();
        assert_eq!(
            policy.ssh_policy.kex[0].regex.as_str(),
            roundtrip.ssh_policy.kex[0].regex.as_str()
        );
    }
}
