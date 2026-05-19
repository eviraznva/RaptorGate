use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::policy::policy_evaluator::{PolicyEvalContext, PolicyEvaluator};
use crate::policy::{Policy, PolicyId};
use crate::rule_tree::Verdict;
use crate::zones::{DefaultPolicy, ZonePair, ZonePairId};

pub struct PolicyEngine {
    evaluators: ArcSwap<HashMap<ZonePairId, PolicyEvaluator>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyEngineError {
    #[error("Zone pair {zone_pair_id} not found in configuration")]
    MissingZonePair { zone_pair_id: ZonePairId },
}

impl PolicyEngine {
    pub fn from_policies(
        policies: &HashMap<PolicyId, Policy>,
        zone_pairs: &HashMap<ZonePairId, ZonePair>,
    ) -> Result<Self, PolicyEngineError> {
        let evaluators = Self::rebuild_evaluators(policies, zone_pairs)?;
        Ok(Self {
            evaluators: ArcSwap::new(Arc::new(evaluators)),
        })
    }

    pub fn rebuild_evaluators(
        policies: &HashMap<PolicyId, Policy>,
        zone_pairs: &HashMap<ZonePairId, ZonePair>,
    ) -> Result<HashMap<ZonePairId, PolicyEvaluator>, PolicyEngineError> {
        let mut grouped: HashMap<ZonePairId, &Policy> = HashMap::new();

        for policy in policies.values() {
            if !zone_pairs.contains_key(&policy.zone_pair_id) {
                return Err(PolicyEngineError::MissingZonePair {
                    zone_pair_id: policy.zone_pair_id.clone(),
                });
            }

            grouped
                .entry(policy.zone_pair_id.clone())
                .and_modify(|existing| {
                    if policy.priority < existing.priority {
                        *existing = policy;
                    }
                })
                .or_insert(policy);
        }

        let mut evaluators = HashMap::new();
        for (zone_pair_id, policy) in grouped {
            let zp = zone_pairs.get(&zone_pair_id).unwrap();
            let orphaned_verdict = match zp.default_policy {
                DefaultPolicy::Allow => Verdict::Allow,
                _ => Verdict::Drop,
            };

            evaluators.insert(
                zone_pair_id,
                PolicyEvaluator::new(policy.rule_tree.clone(), orphaned_verdict),
            );
        }

        Ok(evaluators)
    }

    pub fn update_from_policies(
        &self,
        policies: &HashMap<PolicyId, Policy>,
        zone_pairs: &HashMap<ZonePairId, ZonePair>,
    ) -> Result<(), PolicyEngineError> {
        let evaluators = Self::rebuild_evaluators(policies, zone_pairs)?;
        self.replace(evaluators);
        Ok(())
    }

    pub fn replace(&self, evaluators: HashMap<ZonePairId, PolicyEvaluator>) {
        self.evaluators.store(Arc::new(evaluators));
    }

    pub fn evaluate(
        &self,
        zone_pair_id: &ZonePairId,
        ctx: PolicyEvalContext<'_>,
    ) -> Option<Verdict> {
        let map = self.evaluators.load();
        map.get(zone_pair_id)
            .map(|evaluator| evaluator.evaluate(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::policy_evaluator::PolicyFlowFields;
    use crate::rule_tree::{ArmEnd, ArrivalInfo, Hour, MatchBuilder, MatchKind, Pattern, RuleTree, Weekday};
    use etherparse::{PacketBuilder, SlicedPacket};
    use uuid::Uuid;

    fn create_policy(zone_pair_id: ZonePairId, priority: u32, verdict: Verdict) -> Policy {
        Policy {
            name: format!("policy-{}", priority),
            zone_pair_id,
            priority,
            rule_tree: RuleTree::new(
                MatchBuilder::with_arm(
                    MatchKind::IpVer,
                    Pattern::Wildcard,
                    ArmEnd::Verdict(verdict),
                )
                .build()
                .unwrap(),
            ),
            smtp_policy: crate::policy::SmtpPolicy::default(),
        }
    }

    fn default_arrival() -> ArrivalInfo {
        ArrivalInfo {
            hour: Hour::try_from(14).unwrap(),
            day_of_week: Weekday::Wed,
        }
    }

    fn tcp_packet() -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4([192, 168, 1, 10], [10, 0, 0, 1], 64)
            .tcp(12345, 80, 0, 1024);
        let mut result = Vec::with_capacity(builder.size(0));
        builder.write(&mut result, &[]).unwrap();
        result
    }

    #[test]
    fn builds_engine_with_lowest_priority_policy() {
        let zp_id = ZonePairId::from(Uuid::now_v7());
        let zp = ZonePair {
            src_zone_id: Uuid::now_v7().into(),
            dst_zone_id: Uuid::now_v7().into(),
            default_policy: DefaultPolicy::Drop,
        };

        let p1 = create_policy(zp_id.clone(), 10, Verdict::Drop);
        let p2 = create_policy(zp_id.clone(), 1, Verdict::Allow);

        let mut policies = HashMap::new();
        policies.insert(PolicyId::from(Uuid::now_v7()), p1);
        policies.insert(PolicyId::from(Uuid::now_v7()), p2);

        let mut zone_pairs = HashMap::new();
        zone_pairs.insert(zp_id.clone(), zp);

        let engine = PolicyEngine::from_policies(&policies, &zone_pairs).unwrap();

        let raw = tcp_packet();
        let sliced = SlicedPacket::from_ethernet(&raw).unwrap();
        let arrival = default_arrival();
        let ctx = PolicyEvalContext {
            flow: PolicyFlowFields::from_packet(&sliced).unwrap(),
            arrival: &arrival,
            dns: None,
            dpi: None,
            identity: None,
        };

        assert_eq!(engine.evaluate(&zp_id, ctx), Some(Verdict::Allow));
    }

    #[test]
    fn evaluates_correct_evaluator_per_pair() {
        let zp_id_a = ZonePairId::from(Uuid::now_v7());
        let zp_a = ZonePair {
            src_zone_id: Uuid::now_v7().into(),
            dst_zone_id: Uuid::now_v7().into(),
            default_policy: DefaultPolicy::Drop,
        };

        let zp_id_b = ZonePairId::from(Uuid::now_v7());
        let zp_b = ZonePair {
            src_zone_id: Uuid::now_v7().into(),
            dst_zone_id: Uuid::now_v7().into(),
            default_policy: DefaultPolicy::Drop,
        };

        let p_a = create_policy(zp_id_a.clone(), 1, Verdict::Allow);
        let p_b = create_policy(zp_id_b.clone(), 1, Verdict::Drop);

        let mut policies = HashMap::new();
        policies.insert(PolicyId::from(Uuid::now_v7()), p_a);
        policies.insert(PolicyId::from(Uuid::now_v7()), p_b);

        let mut zone_pairs = HashMap::new();
        zone_pairs.insert(zp_id_a.clone(), zp_a);
        zone_pairs.insert(zp_id_b.clone(), zp_b);

        let engine = PolicyEngine::from_policies(&policies, &zone_pairs).unwrap();

        let raw = tcp_packet();
        let sliced = SlicedPacket::from_ethernet(&raw).unwrap();
        let arrival = default_arrival();
        let ctx = PolicyEvalContext {
            flow: PolicyFlowFields::from_packet(&sliced).unwrap(),
            arrival: &arrival,
            dns: None,
            dpi: None,
            identity: None,
        };

        assert_eq!(
            engine.evaluate(&zp_id_a, ctx.clone()),
            Some(Verdict::Allow)
        );
        assert_eq!(engine.evaluate(&zp_id_b, ctx), Some(Verdict::Drop));
    }

    #[test]
    fn missing_zone_pair_returns_error() {
        let zp_id = ZonePairId::from(Uuid::now_v7());
        let p = create_policy(zp_id.clone(), 1, Verdict::Allow);

        let mut policies = HashMap::new();
        policies.insert(PolicyId::from(Uuid::now_v7()), p);

        let zone_pairs = HashMap::new(); // Missing

        let result = PolicyEngine::from_policies(&policies, &zone_pairs);
        assert!(matches!(
            result,
            Err(PolicyEngineError::MissingZonePair { .. })
        ));
    }

    #[test]
    fn evaluate_returns_none_for_unknown_pair() {
        let engine = PolicyEngine {
            evaluators: ArcSwap::new(Arc::new(HashMap::new())),
        };

        let raw = tcp_packet();
        let sliced = SlicedPacket::from_ethernet(&raw).unwrap();
        let arrival = default_arrival();
        let ctx = PolicyEvalContext {
            flow: PolicyFlowFields::from_packet(&sliced).unwrap(),
            arrival: &arrival,
            dns: None,
            dpi: None,
            identity: None,
        };

        assert_eq!(
            engine.evaluate(&ZonePairId::from(Uuid::now_v7()), ctx),
            None
        );
    }
}
