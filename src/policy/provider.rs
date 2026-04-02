use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use mockall::automock;
use tonic::async_trait;
use uuid::Uuid;


use crate::{config::{AppConfig, DevConfig}, disk_store::ListDiskStore, policy::{Policy, PolicyId, policy_evaluator::PolicyEvaluator}, rule_tree::{ArmEnd, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict, parsing::parse_rule_tree}};

#[async_trait]
#[automock]
pub trait PolicySwapper {
    async fn swap_policies(&self, new_policies: Vec<Policy>) -> Result<(), anyhow::Error>; // should write to disk, thats why its async
}

pub struct DiskPolicyProvider {
    policies: ArcSwap<HashMap<PolicyId, Policy>>,
    evaluator: PolicyEvaluator, //TODO: don't bundle the evaluator with this
    store: ListDiskStore<Policy>,
}

#[async_trait]
impl PolicySwapper for DiskPolicyProvider {
    async fn swap_policies(&self, new_policies: Vec<Policy>) -> Result<(), anyhow::Error> {
        // self.store.save();

        #[allow(clippy::from_iter_instead_of_collect)]
        self.policies.swap(Arc::new(HashMap::from_iter(new_policies.into_iter().map(|pol| (pol.id.clone(), pol)))));
        Ok(())
    }
}

impl DiskPolicyProvider {
    /// # Panics
    /// if dev config cannot be applied
    pub async fn from_loaded(config: &AppConfig) -> anyhow::Result<Self> {
        if let Some(DevConfig { policy_override: Some(policy_override), .. }) = &config.dev_config {
            let dev_policy = Policy { 
                id: Uuid::now_v7().into(),
                name: "DEV OVERRIDE".into(),
                zone_pair_id: Uuid::now_v7().into(),
                priority: 0,
                rule_tree: RuleTree::new(parse_rule_tree(policy_override).expect("COULDNT APPLY DEV POLICY OVERRIDE"))
            };

            let policies = ArcSwap::new(Arc::new(HashMap::from([(dev_policy.id.clone(), dev_policy)])));
            let evaluator = PolicyEvaluator::new(policies.load().values().next().unwrap().rule_tree.clone(), crate::rule_tree::Verdict::Drop);

            tracing::debug!("DEV MODE: Using policy override from environment variable DEV_OVERRIDE_POLICY");

            return Ok(Self { policies, evaluator, store: ListDiskStore::new("policies", "/tmp/".into())})
        }

        let store: ListDiskStore<Policy> = ListDiskStore::new("policies", config.policies_dir.clone());

        if let Ok(loaded) = store.load().await {
            #[allow(clippy::from_iter_instead_of_collect)]
            let policies = HashMap::from_iter(
                loaded.into_iter().map(|prop| (prop.id.into(), prop.contents))
            );

            let evaluator = PolicyEvaluator::new(policies.iter().next().unwrap().1.rule_tree.clone(), crate::rule_tree::Verdict::Drop);

            return Ok(Self { policies: ArcSwap::new(Arc::new(policies)), evaluator, store })
        }

        let default_policy = Policy {
            id: Uuid::now_v7().into(),
            name: "Default policy".into(),
            zone_pair_id: Uuid::now_v7().into(),
            priority: 0,
            rule_tree: RuleTree::new(MatchBuilder::with_arm(
                    MatchKind::IpVer,
                    Pattern::Wildcard,
                    ArmEnd::Verdict(Verdict::DropWarn("Using default drop all policy".into())
                    )).build()?)
        };

        let policies = ArcSwap::new(Arc::new(HashMap::from([(default_policy.id.clone(), default_policy)])));
        let evaluator = PolicyEvaluator::new(policies.load().iter().next().unwrap().1.rule_tree.clone(), crate::rule_tree::Verdict::Drop);

        Ok(Self { policies, evaluator, store})
    }

    pub fn get_policies(&self) -> arc_swap::Guard<Arc<HashMap<PolicyId, Policy>>> {
        self.policies.load()
    }

    pub fn get_evaluator(&self) -> &PolicyEvaluator {
        &self.evaluator
    }
}
