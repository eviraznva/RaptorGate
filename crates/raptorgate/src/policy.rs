use derive_more::{Display, From, Into};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{proto::config::Rule, rule_tree::RuleTree, zones::ZonePairId};
pub use crate::rule_tree::parsing::{RaptorlangError, parse_rule_tree};

pub mod engine;
pub mod policy_evaluator;
pub mod provider;

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
        
        Ok((PolicyId(value.id.try_into()?),
        Policy {
            name: value.name.clone(),
            zone_pair_id: ZonePairId::from(Uuid::parse_str(&value.zone_pair_id)?),
            priority: value.priority,
            rule_tree: RuleTree::new(head),
            smtp_policy,
        }))
    }

    pub fn into_rule(&self, id: PolicyId) -> Rule {
        let is_empty = self.smtp_policy.sender.is_empty()
            && self.smtp_policy.recipient.is_empty()
            && self.smtp_policy.message.is_empty();

        let smtp_matchers = if is_empty {
            None
        } else {
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
            
            Some(crate::proto::config::SmtpMatchers {
                sender: self.smtp_policy.sender.iter().map(to_proto_match).collect(),
                recipient: self.smtp_policy.recipient.iter().map(to_proto_match).collect(),
                message: self.smtp_policy.message.iter().map(to_proto_match).collect(),
            })
        };
        
        Rule {
            id: Uuid::from(id).into(),
            name: self.name.clone(),
            zone_pair_id: Uuid::from(self.zone_pair_id.clone()).into(),
            priority: self.priority,
            content: self.rule_tree.to_string(),
            smtp_matchers,
        }
    }
}

use crate::validation::foreign_keys;
foreign_keys!(Policy { zone_pair_id: ZonePairId });

#[cfg(test)]
mod tests {
    use super::*;

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
}
