use crate::policy_evaluator::PolicyEvaluator;
use crate::rule_tree::parsing::parse_rule_tree;
use crate::rule_tree::{ArmEnd, FieldValue, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict};

use crate::policy::runtime::{
    CompiledPolicyBundle, CompiledPolicyBundleEntry, PolicyBundleMetadata, PolicyBundleSource,
};

#[derive(Debug, thiserror::Error)]
pub enum PolicyCompileError {
    #[error("invalid fallback policy: {0}")]
    Fallback(String),

    #[error("invalid policy source: {0}")]
    Source(String),
}

pub fn compile_fallback(block_icmp: bool) -> Result<CompiledPolicyBundle, PolicyCompileError> {
    build_local_fallback_bundle(block_icmp)
}

pub fn compile_safe_deny() -> Result<CompiledPolicyBundle, PolicyCompileError> {
    let tree = RuleTree::new(
        "safe-deny".into(),
        "Drop everything".into(),
        MatchBuilder::with_arm(
            MatchKind::Protocol,
            Pattern::Wildcard,
            ArmEnd::Verdict(Verdict::Drop),
        ).build()
        .map_err(|err| PolicyCompileError::Fallback(err.to_string()))?,
    );

    Ok(CompiledPolicyBundle::new(
        PolicyBundleMetadata {
            revision_id: None,
            policy_hash: None,
            source: PolicyBundleSource::LocalFallback,
            policy_count: 1,
        },
        vec![CompiledPolicyBundleEntry::new(
            "safe-deny".into(),
            0,
            PolicyEvaluator::new(tree, Verdict::Drop),
        )],
        Verdict::Drop,
    ))
}

pub fn compile_policy_entry(
    name: &str,
    priority: u32,
    policy_source: &str,
) -> Result<CompiledPolicyBundleEntry, PolicyCompileError> {
    let head = parse_rule_tree(policy_source)
        .map_err(|err| PolicyCompileError::Source(err.to_string()))?;

    Ok(CompiledPolicyBundleEntry::new(
        name.to_owned(),
        priority,
        PolicyEvaluator::new(
            RuleTree::new(
                name.to_owned(),
                "Loaded from policy source".into(),
                head,
            ),
            Verdict::Drop,
        ),
    ))
}

pub fn build_runtime_store_bundle(
    revision_id: u64,
    policy_hash: u64,
    policies: Vec<CompiledPolicyBundleEntry>,
    default_verdict: Verdict,
) -> CompiledPolicyBundle {
    let policy_count = policies.len();

    CompiledPolicyBundle::new(
        PolicyBundleMetadata {
            revision_id: Some(revision_id),
            policy_hash: Some(policy_hash),
            source: PolicyBundleSource::RuntimeStore,
            policy_count,
        },
        policies,
        default_verdict,
    )
}

fn build_local_fallback_bundle(block_icmp: bool) -> Result<CompiledPolicyBundle, PolicyCompileError> {
    let tree = if block_icmp {
        RuleTree::new(
            "default".into(),
            "Block ICMP, allow everything else".into(),
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Equal(FieldValue::Protocol(crate::frame::Protocol::Icmp)),
                ArmEnd::Verdict(Verdict::Drop),
            )
            .arm(Pattern::Wildcard, ArmEnd::Verdict(Verdict::Allow))
            .build()
            .map_err(|err| PolicyCompileError::Fallback(err.to_string()))?,
        )
    } else {
        RuleTree::new(
            "default".into(),
            "Allow everything".into(),
            MatchBuilder::with_arm(
                MatchKind::Protocol,
                Pattern::Wildcard,
                ArmEnd::Verdict(Verdict::Allow),
            )
            .build()
            .map_err(|err| PolicyCompileError::Fallback(err.to_string()))?,
        )
    };

    Ok(CompiledPolicyBundle::new(
        PolicyBundleMetadata {
            revision_id: None,
            policy_hash: None,
            source: PolicyBundleSource::LocalFallback,
            policy_count: 1,
        },
        vec![CompiledPolicyBundleEntry::new(
            "default".into(),
            0,
            PolicyEvaluator::new(tree, Verdict::Drop),
        )],
        Verdict::Drop,
    ))
}
