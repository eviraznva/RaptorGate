use crate::control_plane::config::active_config::ActiveConfig;
use crate::policy::runtime::{CompiledPolicy, PolicyMetadata, PolicySource};
use crate::policy_evaluator::PolicyEvaluator;
use crate::rule_tree::{parsing::parse_rule_tree, RuleTree, Verdict};

#[derive(Debug, thiserror::Error)]
pub enum PolicyCompileError {
    #[error("invalid fallback policy: {0}")]
    Fallback(String),
}

pub fn compile_fallback(block_icmp: bool) -> Result<CompiledPolicy, PolicyCompileError> {
    build_compiled_policy(None, None, 0, PolicySource::LocalFallback, block_icmp)
}

pub fn compile_safe_deny() -> Result<CompiledPolicy, PolicyCompileError> {
    let tree = RuleTree::new(
        "safe-deny".into(),
        "Drop everything".into(),
        parse_rule_tree("match protocol { _ : verdict drop }")
            .map_err(|err| PolicyCompileError::Fallback(err.to_string()))?,
    );

    Ok(CompiledPolicy::new(
        PolicyMetadata {
            config_version: None,
            bundle_checksum: None,
            source: PolicySource::LocalFallback,
            rule_count: 0,
        },
        PolicyEvaluator::new(tree, Verdict::Drop),
    ))
}

pub fn compile_from_active_config(
    active_config: &ActiveConfig,
    block_icmp: bool,
    source: PolicySource,
) -> Result<CompiledPolicy, PolicyCompileError> {
    build_compiled_policy(
        Some(active_config.version),
        Some(active_config.bundle_checksum.clone()),
        active_config.rules.len(),
        source,
        block_icmp,
    )
}

fn build_compiled_policy(
    config_version: Option<u64>,
    bundle_checksum: Option<String>,
    rule_count: usize,
    source: PolicySource,
    block_icmp: bool,
) -> Result<CompiledPolicy, PolicyCompileError> {
    let tree = if block_icmp {
        RuleTree::new(
            "default".into(),
            "Block ICMP, allow everything else".into(),
            parse_rule_tree("match protocol { = icmp : verdict drop  _ : verdict allow }")
                .map_err(|err| PolicyCompileError::Fallback(err.to_string()))?,
        )
    } else {
        RuleTree::new(
            "default".into(),
            "Allow everything".into(),
            parse_rule_tree("match protocol { _ : verdict allow }")
                .map_err(|err| PolicyCompileError::Fallback(err.to_string()))?,
        )
    };

    Ok(CompiledPolicy::new(
        PolicyMetadata {
            config_version,
            bundle_checksum,
            source,
            rule_count,
        },
        PolicyEvaluator::new(tree, Verdict::Drop),
    ))
}
