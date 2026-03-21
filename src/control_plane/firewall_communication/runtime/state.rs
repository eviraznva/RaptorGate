use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;
use tracing::{debug, trace, warn};

use crate::policy::runtime::CompiledPolicy;
use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::rgpf_file::RgpfFile;
use crate::control_plane::types::firewall_mode::FirewallMode;
use crate::control_plane::messages::events::heartbeat_event::HeartbeatEvent;
use crate::control_plane::messages::responses::get_status_response::GetStatusResponse;
use crate::control_plane::firewall_communication::runtime::revision_store::RevisionStore;

/// Aktywna rewizja polityki wraz z pełnym buforem `RGPF/1`.
#[derive(Clone)]
pub struct ActiveRevision {
    bytes: Option<Arc<[u8]>>,
    compiled_policy: Arc<CompiledPolicy>,
    revision_id: u64,
    policy_hash: u64,
    rule_count: usize,
}

impl ActiveRevision {
    pub fn fallback(compiled_policy: Arc<CompiledPolicy>) -> Self {
        let metadata = compiled_policy.metadata();
        
        let revision_id = metadata.config_version.unwrap_or(0);
        
        let rule_count = metadata.rule_count;

        Self {
            bytes: None,
            compiled_policy,
            revision_id,
            policy_hash: 0,
            rule_count,
        }
    }

    pub fn from_rgpf(
        bytes: Arc<[u8]>,
        compiled_policy: Arc<CompiledPolicy>,
        revision_id: u64,
        policy_hash: u64,
        rule_count: usize,
    ) -> Self {
        Self {
            bytes: Some(bytes),
            compiled_policy,
            revision_id,
            policy_hash,
            rule_count,
        }
    }

    pub fn compiled_policy(&self) -> &Arc<CompiledPolicy> {
        &self.compiled_policy
    }

    pub fn revision_id(&self) -> u64 {
        self.revision_id
    }

    pub fn policy_hash(&self) -> u64 {
        self.policy_hash
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    pub fn rgpf(&self) -> Result<Option<RgpfFile<'_>>, RgpfError> {
        trace!(
            revision_id = self.revision_id,
            policy_hash = self.policy_hash,
            has_rgpf_bytes = self.bytes.is_some(),
            "Creating RGPF view for active revision"
        );

        match self.bytes.as_deref() {
            Some(bytes) => Ok(Some(RgpfFile::parse(bytes)?)),
            None => Ok(None),
        }
    }
}

/// Pełny snapshot stanu runtime dostępny dla innych warstw.
#[derive(Clone)]
pub struct FirewallRuntimeState {
    pub mode: FirewallMode,
    pub active_revision: Arc<ActiveRevision>,
    pub last_error_code: u32,
}

impl FirewallRuntimeState {
    pub fn compiled_policy(&self) -> &Arc<CompiledPolicy> {
        self.active_revision.compiled_policy()
    }
}

/// Współdzielony stan odczytywany przez handlery IPC i runtime.
#[derive(Clone)]
pub struct FirewallState {
    started_at: Instant,
    revision_store: RevisionStore,
    runtime_tx: watch::Sender<Arc<FirewallRuntimeState>>,
}

impl FirewallState {
    pub fn new(
        revision_store: RevisionStore,
        runtime_tx: watch::Sender<Arc<FirewallRuntimeState>>,
    ) -> Self {
        Self {
            started_at: Instant::now(),
            revision_store,
            runtime_tx,
        }
    }

    pub fn snapshot(&self) -> Arc<FirewallRuntimeState> {
        self.runtime_tx.borrow().clone()
    }

    pub fn revision_store(&self) -> &RevisionStore {
        &self.revision_store
    }

    pub fn activate_revision(&self, active_revision: Arc<ActiveRevision>) {
        let previous = self.snapshot();
        let mut next = (*self.snapshot()).clone();

        next.active_revision = active_revision;
        next.mode = FirewallMode::Normal;
        next.last_error_code = 0;

        debug!(
            previous_mode = ?previous.mode,
            previous_revision_id = previous.active_revision.revision_id(),
            previous_last_error_code = previous.last_error_code,
            next_mode = ?next.mode,
            next_revision_id = next.active_revision.revision_id(),
            next_policy_hash = next.active_revision.policy_hash(),
            next_rule_count = next.active_revision.rule_count(),
            "Activated firewall policy revision"
        );

        self.publish_snapshot(Arc::new(next));
    }

    pub fn mark_policy_error(&self, last_error_code: u32) {
        let previous = self.snapshot();
        let mut next = (*self.snapshot()).clone();

        next.mode = FirewallMode::Degraded;
        next.last_error_code = last_error_code;

        warn!(
            previous_mode = ?previous.mode,
            revision_id = previous.active_revision.revision_id(),
            previous_last_error_code = previous.last_error_code,
            next_mode = ?next.mode,
            next_last_error_code = next.last_error_code,
            "Marked firewall runtime as degraded due to policy error"
        );

        self.publish_snapshot(Arc::new(next));
    }

    pub fn set_last_error_code(&self, last_error_code: u32) {
        let previous = self.snapshot();
        let mut next = (*self.snapshot()).clone();

        next.last_error_code = last_error_code;

        debug!(
            mode = ?next.mode,
            revision_id = next.active_revision.revision_id(),
            previous_last_error_code = previous.last_error_code,
            next_last_error_code = next.last_error_code,
            "Updated firewall runtime error code"
        );

        self.publish_snapshot(Arc::new(next));
    }

    pub fn set_transient_error_code(&self, last_error_code: u32) {
        let previous = self.snapshot();
        let mut next = (*self.snapshot()).clone();

        if next.mode == FirewallMode::Degraded {
            trace!(
                revision_id = next.active_revision.revision_id(),
                current_last_error_code = next.last_error_code,
                ignored_error_code = last_error_code,
                "Ignoring transient error code update because runtime is already degraded"
            );
            return;
        }

        next.last_error_code = last_error_code;

        debug!(
            mode = ?next.mode,
            revision_id = next.active_revision.revision_id(),
            previous_last_error_code = previous.last_error_code,
            next_last_error_code = next.last_error_code,
            "Updated transient firewall runtime error code"
        );

        self.publish_snapshot(Arc::new(next));
    }

    pub fn active_revision(&self) -> Arc<ActiveRevision> {
        self.snapshot().active_revision.clone()
    }

    /// Buduje payload odpowiedzi `GET_STATUS`.
    pub async fn build_status_response(&self) -> GetStatusResponse {
        let state = self.snapshot();

        trace!(
            mode = ?state.mode,
            revision_id = state.active_revision.revision_id(),
            policy_hash = state.active_revision.policy_hash(),
            last_error_code = state.last_error_code,
            uptime_sec = self.started_at.elapsed().as_secs(),
            "Building GET_STATUS response from firewall runtime state"
        );

        GetStatusResponse {
            mode: state.mode,
            loaded_revision_id: state.active_revision.revision_id(),
            policy_hash: state.active_revision.policy_hash(),
            uptime_sec: self.started_at.elapsed().as_secs(),
            last_error_code: state.last_error_code,
        }
    }

    /// Buduje payload eventu `HEARTBEAT`.
    pub async fn build_heartbeat_event(&self) -> HeartbeatEvent {
        let state = self.snapshot();

        trace!(
            mode = ?state.mode,
            revision_id = state.active_revision.revision_id(),
            policy_hash = state.active_revision.policy_hash(),
            last_error_code = state.last_error_code,
            uptime_sec = self.started_at.elapsed().as_secs(),
            "Building HEARTBEAT event from firewall runtime state"
        );

        HeartbeatEvent {
            timestamp_ms: current_timestamp_ms(),
            mode: state.mode,
            loaded_revision_id: state.active_revision.revision_id(),
            policy_hash: state.active_revision.policy_hash(),
            uptime_sec: self.started_at.elapsed().as_secs(),
            last_error_code: state.last_error_code,
        }
    }

    fn publish_snapshot(&self, state: Arc<FirewallRuntimeState>) {
        trace!(
            mode = ?state.mode,
            revision_id = state.active_revision.revision_id(),
            policy_hash = state.active_revision.policy_hash(),
            last_error_code = state.last_error_code,
            "Publishing new firewall runtime state snapshot"
        );
        
        self.runtime_tx.send_replace(state);
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod state_tests {
    use std::sync::Arc;
    use tokio::sync::watch;

    use crate::policy::compiler;
    use crate::control_plane::types::firewall_mode::FirewallMode;
    use super::{ActiveRevision, FirewallRuntimeState, FirewallState};
    use crate::control_plane::firewall_communication::runtime::revision_store::RevisionStore;

    fn build_state() -> FirewallState {
        let policy = Arc::new(compiler::compile_fallback(false).unwrap());
        
        let active_revision = Arc::new(ActiveRevision::fallback(policy.clone()));
        
        let runtime_state = Arc::new(FirewallRuntimeState {
            mode: FirewallMode::Normal,
            active_revision: active_revision.clone(),
            last_error_code: 0,
        });

        let (runtime_tx, _) = watch::channel(runtime_state.clone());

        FirewallState::new(
            RevisionStore::new("/tmp/rg-state-tests"),
            runtime_tx,
        )
    }

    #[test]
    fn fallback_revision_has_no_rgpf_bytes() {
        let policy = Arc::new(compiler::compile_fallback(false).unwrap());
        
        let revision = ActiveRevision::fallback(policy);

        assert_eq!(revision.revision_id(), 0);
        assert_eq!(revision.policy_hash(), 0);
        assert!(revision.rgpf().unwrap().is_none());
    }

    #[test]
    fn setting_error_code_updates_status_snapshot() {
        let state = build_state();

        state.set_last_error_code(203);

        let snapshot = state.snapshot();

        assert_eq!(snapshot.last_error_code, 203);
        assert_eq!(snapshot.mode, FirewallMode::Normal);
        assert_eq!(snapshot.active_revision.revision_id(), 0);
    }

    #[test]
    fn policy_error_sets_degraded_mode_without_changing_revision() {
        let state = build_state();

        state.mark_policy_error(203);

        let snapshot = state.snapshot();

        assert_eq!(snapshot.last_error_code, 203);
        assert_eq!(snapshot.mode, FirewallMode::Degraded);
        assert_eq!(snapshot.active_revision.revision_id(), 0);
    }

    #[test]
    fn activating_revision_clears_error_and_restores_normal_mode() {
        let state = build_state();
        
        let policy = Arc::new(compiler::compile_fallback(false).unwrap());
        
        let active_revision = Arc::new(ActiveRevision::from_rgpf(
            Arc::<[u8]>::from(Vec::<u8>::new().into_boxed_slice()),
            policy,
            320,
            0xABCD,
            1,
        ));

        state.mark_policy_error(203);
        state.activate_revision(active_revision);

        let snapshot = state.snapshot();

        assert_eq!(snapshot.mode, FirewallMode::Normal);
        assert_eq!(snapshot.last_error_code, 0);
        assert_eq!(snapshot.active_revision.revision_id(), 320);
    }

    #[test]
    fn transient_error_does_not_override_policy_degraded_state() {
        let state = build_state();

        state.mark_policy_error(203);
        state.set_transient_error_code(200);

        let snapshot = state.snapshot();

        assert_eq!(snapshot.mode, FirewallMode::Degraded);
        assert_eq!(snapshot.last_error_code, 203);
    }
}
