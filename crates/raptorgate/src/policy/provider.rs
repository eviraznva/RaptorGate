//TODO: concretize the errors

use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use arc_swap::{ArcSwap, Guard};
use mockall::automock;
use tonic::async_trait;
use uuid::Uuid;

use crate::{
    config::{AppConfig, ConfigObserver, DevConfig},
    disk_store::ListDiskStore,
    policy::{
        Policy,
        PolicyId,
        policy_evaluator::{PolicyEvalContext, PolicyEvaluator},
    },
    rule_tree::{ArmEnd, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict, parsing::parse_rule_tree},
    swapper::Swapper,
    zones::{DefaultPolicy, ZonePairId},
};

#[async_trait]
#[automock]
pub trait PolicyManager {
    async fn swap_policies(&self, new_policies: Vec<(PolicyId, Policy)>) -> Result<(), anyhow::Error>; // should write to disk, thats why its async
    fn get_policies(&self) -> Guard<Arc<HashMap<PolicyId, Policy>>>;
    fn get_policy(&self, policy_id: &PolicyId) -> Option<Policy>;
}

#[derive(Clone)]
struct CompiledPolicyEntry {
    evaluator: PolicyEvaluator,
    priority: u32,
}

struct RuntimePolicies {
    global_override: Option<PolicyEvaluator>,
    by_zone_pair: HashMap<ZonePairId, Vec<CompiledPolicyEntry>>,
}

pub struct DiskPolicyProvider {
    swapper: Swapper<PolicyId, Policy>,
    runtime: ArcSwap<RuntimePolicies>,
}

#[async_trait]
impl PolicyManager for DiskPolicyProvider {
    async fn swap_policies(&self, new_policies: Vec<(PolicyId, Policy)>) -> Result<(), anyhow::Error> {
        let runtime_policies = HashMap::from_iter(new_policies.iter().cloned());
        let runtime = compile_runtime_policies(None, &runtime_policies);
        self.swapper.swap(new_policies).await?;
        self.runtime.store(Arc::new(runtime));
        Ok(())
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
            let runtime = compile_runtime_policies(Some(policy_override), &policies);

            tracing::debug!("DEV MODE: Using policy override from environment variable DEV_OVERRIDE_POLICY");

            return Ok(Self {
                swapper: Swapper::new(policies, ListDiskStore::new("policies", "/tmp/".into())),
                runtime: ArcSwap::new(Arc::new(runtime)),
            })
        }

        let store: ListDiskStore<Policy> = ListDiskStore::new("policies", config.data_dir.clone());

        if let Ok(loaded) = store.load().await {
            #[allow(clippy::from_iter_instead_of_collect)]
            let policies = HashMap::from_iter(
                loaded.into_iter().map(|prop| (prop.id.into(), prop.contents))
            );

            if !policies.is_empty() {
                let runtime = compile_runtime_policies(None, &policies);

                tracing::info!("Loaded policies from disk, count: {}", policies.len());
                return Ok(Self {
                    swapper: Swapper::new(policies, store),
                    runtime: ArcSwap::new(Arc::new(runtime)),
                })
            }
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
        let runtime = compile_runtime_policies(None, &policies);

        tracing::info!("No policies found on disk, using default drop all policy.");
        Ok(Self {
            swapper: Swapper::new(policies, store),
            runtime: ArcSwap::new(Arc::new(runtime)),
        })
    }

    pub(crate) fn get_policies(&self) -> arc_swap::Guard<Arc<HashMap<PolicyId, Policy>>> {
        self.swapper.get_all()
    }

    pub(crate) fn uses_global_override(&self) -> bool {
        self.runtime.load().global_override.is_some()
    }

    pub(crate) fn evaluate_global(&self, ctx: PolicyEvalContext<'_, '_>) -> Verdict {
        self.runtime
            .load()
            .global_override
            .as_ref()
            .map(|evaluator| evaluator.evaluate(ctx))
            .unwrap_or(Verdict::Drop)
    }

    pub(crate) fn evaluate_for_zone_pair(
        &self,
        zone_pair_id: &ZonePairId,
        default_policy: DefaultPolicy,
        ctx: PolicyEvalContext<'_, '_>,
    ) -> Verdict {
        let runtime = self.runtime.load();

        if let Some(evaluator) = runtime.global_override.as_ref() {
            return evaluator.evaluate(ctx);
        }

        if let Some(entries) = runtime.by_zone_pair.get(zone_pair_id) {
            for entry in entries {
                if let Some(verdict) = entry.evaluator.evaluate_if_matches(ctx) {
                    return verdict;
                }
            }
        }

        match default_policy {
            DefaultPolicy::Allow => Verdict::Allow,
            DefaultPolicy::Drop | DefaultPolicy::Unspecified => Verdict::Drop,
        }
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

fn compile_runtime_policies(
    policy_override: Option<&str>,
    policies: &HashMap<PolicyId, Policy>,
) -> RuntimePolicies {
    if let Some(policy_override) = policy_override {
        return RuntimePolicies {
            global_override: Some(PolicyEvaluator::new(
                RuleTree::new(
                    parse_rule_tree(policy_override).expect("COULDNT APPLY DEV POLICY OVERRIDE"),
                ),
                Verdict::Drop,
            )),
            by_zone_pair: HashMap::new(),
        };
    }

    let mut by_zone_pair: HashMap<ZonePairId, Vec<CompiledPolicyEntry>> = HashMap::new();

    for policy in policies.values() {
        by_zone_pair
            .entry(policy.zone_pair_id.clone())
            .or_default()
            .push(CompiledPolicyEntry {
                evaluator: PolicyEvaluator::new(policy.rule_tree.clone(), Verdict::Drop),
                priority: policy.priority,
            });
    }

    for entries in by_zone_pair.values_mut() {
        entries.sort_by_key(|entry| entry.priority);
    }

    RuntimePolicies {
        global_override: None,
        by_zone_pair,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    use etherparse::{PacketBuilder, SlicedPacket};
    use crate::rule_tree::ArrivalInfo;

    fn packet(dst_port: u16) -> SlicedPacket<'static> {
        let mut raw = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 10, 10], [192, 168, 20, 10], 64)
            .tcp(40000, dst_port, 1, 65535)
            .write(&mut raw, b"hello")
            .unwrap();

        let leaked = Box::leak(raw.into_boxed_slice());
        SlicedPacket::from_ethernet(leaked).unwrap()
    }

    fn eval_ctx<'a>(packet: &'a SlicedPacket<'a>) -> PolicyEvalContext<'a, 'a> {
        let arrival_time = UNIX_EPOCH + Duration::from_secs(1_700_000_500);
        let arrival = Box::leak(Box::new(ArrivalInfo::from_time(&arrival_time)));

        PolicyEvalContext {
            packet,
            arrival,
            dns: None,
            dpi: None,
            identity: None,
        }
    }

    fn policy(zone_pair_id: &ZonePairId, priority: u32, rule: &str) -> (PolicyId, Policy) {
        (
            Uuid::now_v7().into(),
            Policy {
                name: format!("policy-{priority}"),
                zone_pair_id: zone_pair_id.clone(),
                priority,
                rule_tree: RuleTree::new(parse_rule_tree(rule).unwrap()),
            },
        )
    }

    fn provider_from_policies(policies: HashMap<PolicyId, Policy>) -> DiskPolicyProvider {
        let data_dir = std::env::temp_dir().join(format!("raptorgate-policy-provider-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&data_dir).unwrap();

        DiskPolicyProvider {
            swapper: Swapper::new(
                policies.clone(),
                ListDiskStore::new("policies", data_dir),
            ),
            runtime: ArcSwap::new(Arc::new(compile_runtime_policies(None, &policies))),
        }
    }

    #[test]
    fn evaluate_for_zone_pair_respects_priority_and_fallthrough() {
        let zone_pair_id: ZonePairId = Uuid::now_v7().into();
        let provider = provider_from_policies(HashMap::from([
            policy(&zone_pair_id, 0, "match dst_port { = 53 : verdict allow }"),
            policy(&zone_pair_id, 10, "match ip_ver { = v4 : verdict drop }"),
        ]));

        let dns_packet = packet(53);
        let http_packet = packet(8080);

        assert_eq!(
            provider.evaluate_for_zone_pair(
                &zone_pair_id,
                DefaultPolicy::Allow,
                eval_ctx(&dns_packet),
            ),
            Verdict::Allow,
        );
        assert_eq!(
            provider.evaluate_for_zone_pair(
                &zone_pair_id,
                DefaultPolicy::Allow,
                eval_ctx(&http_packet),
            ),
            Verdict::Drop,
        );
    }

    #[tokio::test]
    async fn swap_policies_rebuilds_runtime_for_new_policy_set() {
        let zone_pair_id: ZonePairId = Uuid::now_v7().into();
        let provider = provider_from_policies(HashMap::from([policy(
            &zone_pair_id,
            0,
            "match ip_ver { = v4 : verdict allow }",
        )]));
        let packet = packet(8080);

        assert_eq!(
            provider.evaluate_for_zone_pair(
                &zone_pair_id,
                DefaultPolicy::Drop,
                eval_ctx(&packet),
            ),
            Verdict::Allow,
        );

        provider
            .swap_policies(vec![policy(
                &zone_pair_id,
                0,
                "match ip_ver { = v4 : verdict drop }",
            )])
            .await
            .unwrap();

        assert_eq!(
            provider.evaluate_for_zone_pair(
                &zone_pair_id,
                DefaultPolicy::Allow,
                eval_ctx(&packet),
            ),
            Verdict::Drop,
        );
    }
}
