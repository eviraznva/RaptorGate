use std::sync::Arc;

use arc_swap::ArcSwap;
use tonic::async_trait;

use crate::{config::{AppConfig, DevConfig}, policy::{Policy, policy_evaluator::PolicyEvaluator}, rule_tree::{RuleTree, parsing::parse_rule_tree}};

#[async_trait]
pub trait PolicySwapper {
    async fn swap_policies(&self, new_policies: Vec<Policy>) -> Result<(), anyhow::Error>; // should write to disk, thats why its async
}

pub struct DiskPolicyProvider {
    policies: ArcSwap<Vec<Policy>>,
    evaluator: PolicyEvaluator //TODO: don't bundle the evaluator with this
}

#[async_trait]
impl PolicySwapper for DiskPolicyProvider {
    async fn swap_policies(&self, new_policies: Vec<Policy>) -> Result<(), anyhow::Error> {
        // TODO: write to disk, serialize with serde or something
        self.policies.swap(new_policies.into());
        Ok(())
    }
}

impl DiskPolicyProvider {
    /// # Panics
    /// if dev config cannot be applied
    pub fn new(config: &AppConfig) -> Self {
        if let Some(DevConfig { policy_override: Some(policy_override), .. }) = &config.dev_config {
            let policies = ArcSwap::new(Arc::new(vec![Policy { 
                id: String::from("dev_policy").into(),
                name: "DEV OVERRIDE".into(),
                zone_pair_id: "dev_zone_pair".into(),
                priority: 0,
                rule_tree: RuleTree::new("DEV OVERRIDE".to_string(), "DEV OVERRIDE".to_string(), parse_rule_tree(policy_override).expect("COULDNT APPLY DEV POLICY OVERRIDE"))
            }]));

            tracing::debug!("DEV MODE: Using policy override from environment variable DEV_OVERRIDE_POLICY");
            let evaluator = PolicyEvaluator::new(policies.load()[0].rule_tree.clone(), crate::rule_tree::Verdict::Drop);

            Self { policies, evaluator}
        } else {
            todo!("Implement DiskPolicyProvider to load policies from disk")
        }
    }

    pub fn get_policies(&self) -> Arc<Vec<Policy>> {
        self.policies.load().clone()
    }

    pub fn get_evaluator(&self) -> &PolicyEvaluator {
        &self.evaluator
    }
}
