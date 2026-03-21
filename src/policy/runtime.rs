use std::sync::Arc;

use crate::frame::Frame;
use crate::rule_tree::Verdict;
use crate::policy_evaluator::PolicyEvaluator;

#[derive(Clone, Debug)]
pub enum PolicyBundleSource {
    LocalFallback,
    RuntimeStore,
}

#[derive(Clone, Debug)]
pub struct PolicyBundleMetadata {
    pub revision_id: Option<u64>,
    pub policy_hash: Option<u64>,
    pub source: PolicyBundleSource,
    pub policy_count: usize,
}

#[derive(Clone)]
pub struct CompiledPolicyBundleEntry {
    name: String,
    priority: u32,
    evaluator: Arc<PolicyEvaluator>,
}

impl CompiledPolicyBundleEntry {
    pub(crate) fn new(name: String, priority: u32, evaluator: PolicyEvaluator) -> Self {
        Self {
            name,
            priority,
            evaluator: Arc::new(evaluator),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn priority(&self) -> u32 {
        self.priority
    }

    pub(crate) fn evaluator(&self) -> &PolicyEvaluator {
        self.evaluator.as_ref()
    }
}

#[derive(Clone)]
pub struct CompiledPolicyBundle {
    metadata: PolicyBundleMetadata,
    policies: Vec<CompiledPolicyBundleEntry>,
    default_verdict: Verdict,
}

impl CompiledPolicyBundle {
    pub(crate) fn new(
        metadata: PolicyBundleMetadata,
        mut policies: Vec<CompiledPolicyBundleEntry>,
        default_verdict: Verdict,
    ) -> Self {
        policies.sort_by_key(CompiledPolicyBundleEntry::priority);

        Self {
            metadata,
            policies,
            default_verdict,
        }
    }

    pub fn metadata(&self) -> &PolicyBundleMetadata {
        &self.metadata
    }

    pub fn policies(&self) -> &[CompiledPolicyBundleEntry] {
        &self.policies
    }

    pub(crate) fn default_verdict(&self) -> &Verdict {
        &self.default_verdict
    }

    pub fn evaluate<T>(&self, frame: &T) -> Verdict where T: Frame
    {
        for policy in &self.policies {
            if let Some(verdict) = policy.evaluator().evaluate(frame) {
                return verdict;
            }
        }

        self.default_verdict.clone()
    }
}
