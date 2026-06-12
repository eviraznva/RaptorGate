//TODO: concretize the errors

use std::{collections::HashMap, sync::Arc};

use arc_swap::Guard;
use mockall::automock;
use tonic::async_trait;
use uuid::Uuid;


use crate::{config::{AppConfig, ConfigObserver, DevConfig}, disk_store::ListDiskStore, policy::{Policy, PolicyId}, rule_tree::{ArmEnd, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict, parsing::parse_rule_tree}, swapper::Swapper};

#[derive(Debug, thiserror::Error)]
pub enum PolicyProviderError {
    #[error("Failed to swap policies: {0}")]
    SwapError(#[from] anyhow::Error),
    #[error("Rule tree parsing error: {0}")]
    ParseError(#[from] crate::rule_tree::parsing::RaptorlangError),
    #[error("Rule error: {0}")]
    RuleError(#[from] crate::rule_tree::RuleError),
}

#[async_trait]
#[automock]
pub trait PolicyManager {
    async fn swap_policies(&self, new_policies: Vec<(PolicyId, Policy)>) -> Result<(), PolicyProviderError>; // should write to disk, thats why its async
    fn get_policies(&self) -> Guard<Arc<HashMap<PolicyId, Policy>>>;
    fn get_policy(&self, policy_id: &PolicyId) -> Option<Policy>;
}

pub struct DiskPolicyProvider {
    swapper: Swapper<PolicyId, Policy>,
}

impl DiskPolicyProvider {
    pub fn from_policies(policies: HashMap<PolicyId, Policy>, data_dir: std::path::PathBuf) -> Self {
        Self {
            swapper: Swapper::new(policies, crate::disk_store::ListDiskStore::new("policies", data_dir)),
        }
    }
}

#[async_trait]
impl PolicyManager for DiskPolicyProvider {
    async fn swap_policies(&self, new_policies: Vec<(PolicyId, Policy)>) -> Result<(), PolicyProviderError> {
        self.swapper.swap(new_policies).await.map_err(Into::into)
    }

    fn get_policies(&self) -> Guard<Arc<HashMap<PolicyId, Policy>>> {
        self.swapper.get_all()
    }

    fn get_policy(&self, policy_id: &PolicyId) -> Option<Policy> {
        self.swapper.get(policy_id)
    }
}

pub fn default_drop_policy() -> anyhow::Result<(PolicyId, Policy)> {
    let policy = Policy {
        name: "Default policy".into(),
        zone_pair_id: Uuid::nil().into(),
        priority: 0,
        rule_tree: RuleTree::new(MatchBuilder::with_arm(
                MatchKind::IpVer,
                Pattern::Wildcard,
                ArmEnd::Verdict(Verdict::DropWarn("Using default drop all policy".into())
                )).build()?),
        smtp_policy: crate::policy::SmtpPolicy::default(),
        ssh_policy: crate::policy::SshPolicy::default(),
    };

    Ok((Uuid::nil().into(), policy))
}

impl DiskPolicyProvider {
    /// # Panics
    /// if dev config cannot be applied
    pub async fn from_loaded(config: &AppConfig) -> anyhow::Result<Self> {
        if let Some(DevConfig { policy_override: Some(policy_override), .. }) = &config.dev_config {
            let dev_policy = Policy { 
                name: "DEV OVERRIDE".into(),
                zone_pair_id: Uuid::nil().into(),
                priority: 0,
                rule_tree: RuleTree::new(parse_rule_tree(policy_override).expect("COULDNT APPLY DEV POLICY OVERRIDE")),
                smtp_policy: crate::policy::SmtpPolicy::default(),
                ssh_policy: crate::policy::SshPolicy::default(),
            };

            let policies = HashMap::from([(Uuid::nil().into(), dev_policy)]);

            tracing::debug!("DEV MODE: Using policy override from environment variable DEV_OVERRIDE_POLICY");

            return Ok(Self { swapper: Swapper::new(policies, ListDiskStore::new("policies", "/tmp/".into())) })
        }

        let store: ListDiskStore<Policy> = ListDiskStore::new("policies", config.data_dir.clone());

        if let Ok(loaded) = store.load().await {
            #[allow(clippy::from_iter_instead_of_collect)]
            let policies = HashMap::from_iter(
                loaded.into_iter().map(|prop| (prop.id.into(), prop.contents))
            );

            tracing::info!("Loaded policies from disk, count: {}", policies.len());
            return Ok(Self { swapper: Swapper::new(policies, store) })
        }

        let policies = HashMap::from([default_drop_policy()?]);

        tracing::info!("No policies found on disk, using default drop all policy.");
        Ok(Self { swapper: Swapper::new(policies, store)})
    }

    pub fn get_policies(&self) -> arc_swap::Guard<Arc<HashMap<PolicyId, Policy>>> {
        self.swapper.get_all()
    }
}

#[tonic::async_trait]
impl ConfigObserver for DiskPolicyProvider {
    async fn on_config_change(&self, new_config: &AppConfig) -> anyhow::Result<()> {
        tracing::info!(
            data_dir = ?new_config.data_dir,
            dev_mode = new_config.dev_config.is_some(),
            "DiskPolicyProvider: config changed (stub — no reinitialization yet)"
        );
        Ok(())
    }
}
