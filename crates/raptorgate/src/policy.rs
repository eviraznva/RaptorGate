use derive_more::{Display, From, Into};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{proto::config::Rule, rule_tree::RuleTree, zones::ZonePairId};
pub use crate::rule_tree::parsing::{RaptorlangError, parse_rule_tree};

pub mod engine;
pub mod policy_evaluator;
pub mod provider;
pub mod nat;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpPolicy {
    #[serde(with = "serde_regex")]
    pub sender: Regex,
    #[serde(with = "serde_regex")]
    pub recipient: Regex,
    #[serde(with = "serde_regex")]
    pub message: Regex
}

impl SmtpPolicy {
    pub fn default() -> Self {
        Self {
            sender: Regex::new("$^").unwrap(),
            recipient: Regex::new("$^").unwrap(),
            message: Regex::new("$^").unwrap(),
        }
    }

    #[cfg(test)]
    pub fn permissive() -> Self {
        Self {
            sender: Regex::new(".*").unwrap(),
            recipient: Regex::new(".*").unwrap(),
            message: Regex::new(".*").unwrap(),
        }
    }

}
#[derive(Clone, Debug, PartialEq, Eq, Hash, From, Into, Deserialize, Serialize, Display)]
pub struct PolicyId(Uuid);

impl Policy {
    pub fn try_from_rule(value: Rule) -> Result<(PolicyId, Self), anyhow::Error> {
        let head = parse_rule_tree(&value.content)?;
        
        let smtp_policy = if let Some(matchers) = value.smtp_matchers {
            let sender = if matchers.smtp_sender.is_empty() {
                Regex::new("$^").unwrap()
            } else {
                Regex::new(&matchers.smtp_sender)
                    .map_err(|e| anyhow::anyhow!("Invalid smtp_sender regex: {}", e))?
            };
            
            let recipient = if matchers.smtp_recipient.is_empty() {
                Regex::new("$^").unwrap()
            } else {
                Regex::new(&matchers.smtp_recipient)
                    .map_err(|e| anyhow::anyhow!("Invalid smtp_recipient regex: {}", e))?
            };
            
            let message = if matchers.smtp_message.is_empty() {
                Regex::new("$^").unwrap()
            } else {
                Regex::new(&matchers.smtp_message)
                    .map_err(|e| anyhow::anyhow!("Invalid smtp_message regex: {}", e))?
            };
            
            SmtpPolicy { sender, recipient, message }
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
        let smtp_matchers = {
            let sender_pattern = self.smtp_policy.sender.as_str();
            let recipient_pattern = self.smtp_policy.recipient.as_str();
            let message_pattern = self.smtp_policy.message.as_str();
            
            if sender_pattern == "$^" && recipient_pattern == "$^" && message_pattern == "$^" {
                None
            } else {
                Some(crate::proto::config::SmtpMatchers {
                    smtp_sender: sender_pattern.to_string(),
                    smtp_recipient: recipient_pattern.to_string(),
                    smtp_message: message_pattern.to_string(),
                })
            }
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
