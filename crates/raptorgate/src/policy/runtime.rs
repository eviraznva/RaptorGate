use std::sync::Arc;

use derive_more::Display;

use crate::policy_evaluator::PolicyEvaluator;

#[derive(Clone, Debug)]
pub enum PolicySource {
    LocalFallback,
    Snapshot,
    Backend,
    SnapshotThenBackend,
}

#[derive(Clone, Debug)]
pub struct PolicyMetadata {
    pub config_version: Option<u64>,
    pub bundle_checksum: Option<String>,
    pub source: PolicySource,
    pub rule_count: usize,
}

#[derive(Clone)]
pub struct CompiledPolicy {
    metadata: PolicyMetadata,
    evaluator: Arc<PolicyEvaluator>,
}

impl CompiledPolicy {
    pub(crate) fn new(metadata: PolicyMetadata, evaluator: PolicyEvaluator) -> Self {
        Self {
            metadata,
            evaluator: Arc::new(evaluator),
        }
    }

    pub fn metadata(&self) -> &PolicyMetadata {
        &self.metadata
    }

    pub(crate) fn evaluator(&self) -> &PolicyEvaluator {
        self.evaluator.as_ref()
    }
}
