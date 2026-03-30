use derive_more::From;
use thiserror::Error;

use crate::{proto::config::Rule, rule_tree::RuleTree};
pub use crate::rule_tree::{parsing::{RaptorlangError, parse_rule_tree}};

mod policy_evaluator;
pub mod provider;
pub mod nat;

// tonic::include_proto!("raptorgate.config");


// TODO: jak na razie to z tego co widze backend zapisuje json z regułami. To raczej powinna być w całości odpowiedzialność firewalla.
pub struct Policy {
    pub id: PolicyId,
    pub name: String,
    // pub description: Option<String>,
    pub zone_pair_id: String,
    // pub is_active: bool,
    pub priority: u32,
    // pub created_at: SystemTime,
    // pub updated_at: SystemTime,
    // pub created_by: String,

    pub rule_tree: RuleTree,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, From)]
pub struct PolicyId(String);

impl TryFrom<Rule> for Policy {
    type Error = RaptorlangError;
    fn try_from(value: Rule) -> Result<Self, Self::Error> {
        let rule_tree = parse_rule_tree(&value.content)?;
        Ok(Policy {
            id: PolicyId(value.id),
            name: value.name.clone(),
            zone_pair_id: value.zone_pair_id,
            priority: value.priority,
            rule_tree: RuleTree::new(value.name.clone(), "TODO:".into(), rule_tree), // TODO: jak api wroci to dac tu Match i wyjebac RuleTree
        })
    }
}
