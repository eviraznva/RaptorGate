//TODO: concretize the errors

use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use arc_swap::{ArcSwap, Guard};
use mockall::automock;
use tonic::async_trait;
use uuid::Uuid;


use crate::{config::{AppConfig, DevConfig}, config_provider::ConfigObserver, disk_store::{ListDiskStore, SavedProperty}, policy::{Policy, PolicyId, policy_evaluator::PolicyEvaluator}, rule_tree::{ArmEnd, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict, parsing::parse_rule_tree}};

#[async_trait]
#[automock]
pub trait PolicyManager {
    async fn swap_policies(&self, new_policies: Vec<(PolicyId, Policy)>) -> Result<(), anyhow::Error>; // should write to disk, thats why its async
    fn get_policies(&self) -> Guard<Arc<HashMap<PolicyId, Policy>>>;
    fn get_policy(&self, policy_id: &PolicyId) -> Option<Policy>;
}

pub struct DiskPolicyProvider {
    policies: ArcSwap<HashMap<PolicyId, Policy>>,
    evaluator: PolicyEvaluator, //TODO: don't bundle the evaluator with this
    store: ListDiskStore<Policy>,
}

#[async_trait]
impl PolicyManager for DiskPolicyProvider {
    async fn swap_policies(&self, new_policies: Vec<(PolicyId, Policy)>) -> Result<(), anyhow::Error> {
        let old_policies = self.policies.load();

        self.store.save(new_policies.iter().cloned().map(|pol| SavedProperty {
            id: pol.0.into(), contents: pol.1 
        }).collect()).await?;

        let loaded = self.store.load().await; // we load to check if we saved properly
        match loaded {
            Ok(loaded) => {
                let map = loaded.into_iter().map(|prop| (prop.id.into(), prop.contents)).collect();
                self.policies.swap(Arc::new(map));
            }

            Err(err) => {
                tracing::error!(error = %err, "failed to load policies after saving new policies");
                self.store.save(old_policies.iter().map(|pol| SavedProperty {
                    id: pol.0.clone().into(), contents: pol.1.clone() 
                }).collect()).await?; // try to restore old policies, if this fails we're in a really bad state and there's not much we can do about it. TODO: emit a notification event
                return Err(err.into());
            }
        }

        #[allow(clippy::from_iter_instead_of_collect)]
        Ok(())
    }

    fn get_policies(&self) -> Guard<Arc<HashMap<PolicyId, Policy>>> {
        self.policies.load()
    }

    fn get_policy(&self, policy_id: &PolicyId) -> Option<Policy> {
        self.policies.load().get(policy_id).cloned()
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

            let policies = ArcSwap::new(Arc::new(HashMap::from([(Uuid::now_v7().into(), dev_policy)])));
            let evaluator = PolicyEvaluator::new(policies.load().values().next().unwrap().rule_tree.clone(), crate::rule_tree::Verdict::Drop);

            tracing::debug!("DEV MODE: Using policy override from environment variable DEV_OVERRIDE_POLICY");

            return Ok(Self { policies, evaluator, store: ListDiskStore::new("policies", "/tmp/".into())})
        }

        let store: ListDiskStore<Policy> = ListDiskStore::new("policies", config.data_dir.clone());

        if let Ok(loaded) = store.load().await {
            #[allow(clippy::from_iter_instead_of_collect)]
            let policies = HashMap::from_iter(
                loaded.into_iter().map(|prop| (prop.id.into(), prop.contents))
            );

            let evaluator = PolicyEvaluator::new(policies.iter().next().unwrap().1.rule_tree.clone(), crate::rule_tree::Verdict::Drop);

            tracing::info!("Loaded policies from disk, count: {}", policies.len());
            return Ok(Self { policies: ArcSwap::new(Arc::new(policies)), evaluator, store })
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

        let policies = ArcSwap::new(Arc::new(HashMap::from([(Uuid::now_v7().into(), default_policy)])));
        let evaluator = PolicyEvaluator::new(policies.load().iter().next().unwrap().1.rule_tree.clone(), crate::rule_tree::Verdict::Drop);

        tracing::info!("No policies found on disk, using default drop all policy.");
        Ok(Self { policies, evaluator, store})
    }

    pub fn get_policies(&self) -> arc_swap::Guard<Arc<HashMap<PolicyId, Policy>>> {
        self.policies.load()
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
