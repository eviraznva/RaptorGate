//TODO: concretize the errors

use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use arc_swap::Guard;
use mockall::automock;
use tonic::async_trait;
use uuid::Uuid;


use crate::{config::{AppConfig, ConfigObserver, DevConfig}, disk_store::ListDiskStore, policy::{Policy, PolicyId, policy_evaluator::PolicyEvaluator}, rule_tree::{ArmEnd, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict, parsing::parse_rule_tree}, swapper::Swapper};

#[async_trait]
#[automock]
pub trait PolicyManager {
    async fn swap_policies(&self, new_policies: Vec<(PolicyId, Policy)>) -> Result<(), anyhow::Error>; // should write to disk, thats why its async
    fn get_policies(&self) -> Guard<Arc<HashMap<PolicyId, Policy>>>;
    fn get_policy(&self, policy_id: &PolicyId) -> Option<Policy>;
}

pub struct DiskPolicyProvider {
    swapper: Swapper<PolicyId, Policy>,
    evaluator: PolicyEvaluator, //TODO: don't bundle the evaluator with this
}

#[async_trait]
impl PolicyManager for DiskPolicyProvider {
    async fn swap_policies(&self, new_policies: Vec<(PolicyId, Policy)>) -> Result<(), anyhow::Error> {
        self.swapper.swap(new_policies).await
    }

    fn get_policies(&self) -> Guard<Arc<HashMap<PolicyId, Policy>>> {
        self.swapper.get_all()
    }

    fn get_policy(&self, policy_id: &PolicyId) -> Option<Policy> {
        self.swapper.get(policy_id)
    }
}

impl DiskPolicyProvider {
    /// # Panics
    /// if dev config cannot be applied
    pub async fn from_loaded(config: &AppConfig) -> anyhow::Result<Self> {
        if let Some(DevConfig { policy_override: Some(policy_override), .. }) = &config.dev_config {
            let dev_policy = Policy { 
                name: "DEV OVERRIDE".into(),
                zone_pair_id: Uuid::now_v7().into(),
                priority: 0,
                rule_tree: RuleTree::new(parse_rule_tree(policy_override).expect("COULDNT APPLY DEV POLICY OVERRIDE"))
            };

            let policies = HashMap::from([(Uuid::now_v7().into(), dev_policy)]);
            let evaluator = PolicyEvaluator::new(policies.values().next().unwrap().rule_tree.clone(), crate::rule_tree::Verdict::Drop);

            tracing::debug!("DEV MODE: Using policy override from environment variable DEV_OVERRIDE_POLICY");

            return Ok(Self { swapper: Swapper::new(policies, ListDiskStore::new("policies", "/tmp/".into())), evaluator })
        }

        let store: ListDiskStore<Policy> = ListDiskStore::new("policies", config.data_dir.clone());

        if let Ok(loaded) = store.load().await {
            #[allow(clippy::from_iter_instead_of_collect)]
            let policies = HashMap::from_iter(
                loaded.into_iter().map(|prop| (prop.id.into(), prop.contents))
            );

            let evaluator = PolicyEvaluator::new(policies.iter().next().unwrap().1.rule_tree.clone(), crate::rule_tree::Verdict::Drop);

            tracing::info!("Loaded policies from disk, count: {}", policies.len());
            return Ok(Self { swapper: Swapper::new(policies, store), evaluator })
        }

        let default_policy = Policy {
            name: "Default policy".into(),
            zone_pair_id: Uuid::now_v7().into(),
            priority: 0,
            rule_tree: RuleTree::new(MatchBuilder::with_arm(
                    MatchKind::IpVer,
                    Pattern::Wildcard,
                    ArmEnd::Verdict(Verdict::DropWarn("Using default drop all policy".into())
                    )).build()?)
        };

        let policies = HashMap::from([(Uuid::now_v7().into(), default_policy)]);
        let evaluator = PolicyEvaluator::new(policies.iter().next().unwrap().1.rule_tree.clone(), crate::rule_tree::Verdict::Drop);

        tracing::info!("No policies found on disk, using default drop all policy.");
        Ok(Self { swapper: Swapper::new(policies, store), evaluator})
    }

    pub fn get_policies(&self) -> arc_swap::Guard<Arc<HashMap<PolicyId, Policy>>> {
        self.swapper.get_all()
    }

    pub fn get_evaluator(&self) -> &PolicyEvaluator {
        &self.evaluator
    }
}

#[tonic::async_trait]
impl ConfigObserver for DiskPolicyProvider {
    async fn on_config_change(&self, new_config: &AppConfig) -> Result<()> {
        tracing::info!(
            data_dir = ?new_config.data_dir,
            dev_mode = new_config.dev_config.is_some(),
            "DiskPolicyProvider: config changed (stub — no reinitialization yet)"
        );
        Ok(())
    }
}
