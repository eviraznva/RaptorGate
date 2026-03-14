use std::sync::Arc;
use arc_swap::ArcSwap;

use crate::control_plane::runtime_firewall_rules::RuntimeFirewallRules;

#[derive(Debug, Clone)]
pub struct RuntimeRulesHandle {
    inner: Arc<ArcSwap<RuntimeFirewallRules>>,
}

impl RuntimeRulesHandle {
    pub fn new(initial: RuntimeFirewallRules) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    pub fn load(&self) -> Arc<RuntimeFirewallRules> {
        self.inner.load_full()
    }

    pub fn store(&self, rules: RuntimeFirewallRules) {
        self.inner.store(Arc::new(rules));
    }
}