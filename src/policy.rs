use derive_more::{From, Into};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{proto::config::Rule, rule_tree::RuleTree};
pub use crate::rule_tree::{parsing::{RaptorlangError, parse_rule_tree}};

mod policy_evaluator;
pub mod provider;
pub mod nat;

// tonic::include_proto!("raptorgate.config");


// TODO: jak na razie to z tego co widze backend zapisuje json z regułami. To raczej powinna być w całości odpowiedzialność firewalla.
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, From, Into, Deserialize, Serialize)]
pub struct PolicyId(Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, From, Into, Deserialize, Serialize)]
pub struct ZonePairId(Uuid);

impl Policy {
    pub fn try_from_rule(value: Rule) -> Result<(PolicyId, Self), anyhow::Error> {
        let head = parse_rule_tree(&value.content)?;
        Ok((PolicyId(value.id.try_into()?),
        Policy {
            // id: PolicyId(value.id.try_into()?),
            name: value.name.clone(),
            zone_pair_id: ZonePairId(value.zone_pair_id.try_into()?),
            priority: value.priority,
            rule_tree: RuleTree::new(head), // TODO: jak api wroci to dac tu Match i wyjebac RuleTree
        }))
    }
}
