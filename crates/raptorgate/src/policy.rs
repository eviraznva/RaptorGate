use derive_more::{Display, From, Into};
use serde::{Deserialize, Serialize};
use thiserror::Error;
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
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, From, Into, Deserialize, Serialize, Display)]
pub struct PolicyId(Uuid);

impl Policy {
    pub fn try_from_rule(value: Rule) -> Result<(PolicyId, Self), anyhow::Error> {
        let head = parse_rule_tree(&value.content)?;
        Ok((PolicyId(value.id.try_into()?),
        Policy {
            // id: PolicyId(value.id.try_into()?),
            name: value.name.clone(),
            zone_pair_id: ZonePairId::from(Uuid::parse_str(&value.zone_pair_id)?),
            priority: value.priority,
            rule_tree: RuleTree::new(head), // TODO: jak api wroci to dac tu Match i wyjebac RuleTree
        }))
    }

    pub fn into_rule(&self, id: PolicyId) -> Rule {
        Rule {
            id: Uuid::from(id).into(),
            name: self.name.clone(),
            zone_pair_id: Uuid::from(self.zone_pair_id.clone()).into(),
            priority: self.priority,
            content: self.rule_tree.to_string(), // TODO: jak api wroci to dac tu Match i wyjebac RuleTree
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
