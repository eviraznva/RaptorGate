use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};

use crate::tls::transparent_redirect::{TABLE_NAME, TransparentRedirect};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsRedirectConfig {
    pub listen_addr: SocketAddr,
    pub capture_interfaces: Vec<String>,
    pub inspection_ports: Vec<u16>,
    pub local_addresses: Vec<IpAddr>,
}

impl TlsRedirectConfig {
    pub fn new(
        listen_addr: SocketAddr,
        capture_interfaces: Vec<String>,
        inspection_ports: Vec<u16>,
        local_addresses: Vec<IpAddr>,
    ) -> Self {
        let mut capture_interfaces: Vec<String> = capture_interfaces
            .into_iter()
            .map(|iface| iface.trim().to_string())
            .filter(|iface| !iface.is_empty())
            .collect();
        capture_interfaces.sort();
        capture_interfaces.dedup();

        let mut inspection_ports = inspection_ports;
        inspection_ports.sort_unstable();
        inspection_ports.dedup();

        let mut local_addresses = local_addresses;
        local_addresses.sort_unstable();
        local_addresses.dedup();

        Self {
            listen_addr,
            capture_interfaces,
            inspection_ports,
            local_addresses,
        }
    }

    fn to_redirect(&self) -> Result<TransparentRedirect> {
        TransparentRedirect::new(
            self.listen_addr,
            self.capture_interfaces.clone(),
            self.inspection_ports.clone(),
            self.local_addresses.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TlsRedirectDesiredState {
    Disabled,
    Enabled(TlsRedirectConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRedirectReconcileOutcome {
    Noop,
    Installed,
    Uninstalled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRedirectLastApplyResult {
    pub generation: u64,
    pub state_hash: u64,
    pub outcome: Option<TlsRedirectReconcileOutcome>,
    pub error: Option<String>,
}

pub trait TlsRedirectCommandRunner: Send + Sync {
    fn table_exists(&self, table_name: &str) -> Result<bool>;
    fn delete_table(&self, table_name: &str) -> Result<()>;
    fn apply_script(&self, script: &str) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct SystemNftRunner;

impl TlsRedirectCommandRunner for SystemNftRunner {
    fn table_exists(&self, table_name: &str) -> Result<bool> {
        let status = Command::new("nft")
            .args(["list", "table", "inet", table_name])
            .status()
            .context("Failed to probe nftables table")?;

        Ok(status.success())
    }

    fn delete_table(&self, table_name: &str) -> Result<()> {
        let delete_status = Command::new("nft")
            .args(["delete", "table", "inet", table_name])
            .status()
            .context("Failed to delete existing nftables table")?;

        if !delete_status.success() {
            bail!("nft delete table inet {table_name} failed");
        }

        Ok(())
    }

    fn apply_script(&self, script: &str) -> Result<()> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start nft")?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .context("Failed to open nft stdin")?;
            stdin
                .write_all(script.as_bytes())
                .context("Failed to write nft rules")?;
        }

        let output = child
            .wait_with_output()
            .context("Failed to wait for nft")?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nft apply failed: {stderr}");
    }
}

pub struct TlsRedirectManager {
    runner: Arc<dyn TlsRedirectCommandRunner>,
    applied_state: Mutex<Option<TlsRedirectDesiredState>>,
    last_apply_result: Mutex<Option<TlsRedirectLastApplyResult>>,
    generation: AtomicU64,
}

impl TlsRedirectManager {
    pub fn new() -> Self {
        Self::with_runner(Arc::new(SystemNftRunner))
    }

    pub fn with_runner(runner: Arc<dyn TlsRedirectCommandRunner>) -> Self {
        Self {
            runner,
            applied_state: Mutex::new(None),
            last_apply_result: Mutex::new(None),
            generation: AtomicU64::new(1),
        }
    }

    pub fn last_apply_result(&self) -> Option<TlsRedirectLastApplyResult> {
        self.last_apply_result.lock().unwrap().clone()
    }

    pub fn reconcile(&self, desired: TlsRedirectDesiredState) -> Result<TlsRedirectReconcileOutcome> {
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        let state_hash = state_hash(&desired);
        tracing::info!(
            event = "tls.redirect.reconcile.started",
            generation,
            state_hash,
            "TLS redirect reconcile started"
        );

        let outcome = match self.reconcile_inner(desired.clone()) {
            Ok(outcome) => {
                self.record_last_result(generation, state_hash, Some(outcome), None);
                Ok(outcome)
            }
            Err(err) => {
                tracing::error!(
                    event = "tls.redirect.reconcile.failed",
                    generation,
                    state_hash,
                    error = %err,
                    "TLS redirect reconcile failed"
                );
                self.record_last_result(generation, state_hash, None, Some(err.to_string()));
                Err(err)
            }
        }?;

        match outcome {
            TlsRedirectReconcileOutcome::Installed => tracing::info!(
                event = "tls.redirect.reconcile.installed",
                generation,
                state_hash,
                "TLS redirect installed"
            ),
            TlsRedirectReconcileOutcome::Uninstalled => tracing::info!(
                event = "tls.redirect.reconcile.uninstalled",
                generation,
                state_hash,
                "TLS redirect uninstalled"
            ),
            TlsRedirectReconcileOutcome::Noop => tracing::debug!(
                event = "tls.redirect.reconcile.noop",
                generation,
                state_hash,
                "TLS redirect unchanged"
            ),
        }

        Ok(outcome)
    }

    fn reconcile_inner(&self, desired: TlsRedirectDesiredState) -> Result<TlsRedirectReconcileOutcome> {
        match desired {
            TlsRedirectDesiredState::Disabled => {
                let had_applied = self.applied_state.lock().unwrap().take().is_some();
                let removed = self.uninstall_if_present()?;
                if had_applied || removed {
                    Ok(TlsRedirectReconcileOutcome::Uninstalled)
                } else {
                    Ok(TlsRedirectReconcileOutcome::Noop)
                }
            }
            TlsRedirectDesiredState::Enabled(config) if config.capture_interfaces.is_empty() => {
                self.applied_state.lock().unwrap().take();
                self.uninstall_if_present()?;
                Err(anyhow!("TLS redirect enabled with no capture interfaces"))
            }
            TlsRedirectDesiredState::Enabled(config) => {
                let desired = TlsRedirectDesiredState::Enabled(config.clone());
                if self.applied_state.lock().unwrap().as_ref() == Some(&desired) {
                    return Ok(TlsRedirectReconcileOutcome::Noop);
                }

                let redirect = config.to_redirect()?;
                if let Err(err) = self.replace_table(&redirect.render_script()) {
                    self.applied_state.lock().unwrap().take();
                    return Err(err);
                }
                *self.applied_state.lock().unwrap() = Some(desired);
                Ok(TlsRedirectReconcileOutcome::Installed)
            }
        }
    }

    fn replace_table(&self, script: &str) -> Result<()> {
        self.uninstall_if_present()?;
        self.runner.apply_script(script)
    }

    fn uninstall_if_present(&self) -> Result<bool> {
        if !self.runner.table_exists(TABLE_NAME)? {
            return Ok(false);
        }
        self.runner.delete_table(TABLE_NAME)?;
        Ok(true)
    }

    fn record_last_result(
        &self,
        generation: u64,
        state_hash: u64,
        outcome: Option<TlsRedirectReconcileOutcome>,
        error: Option<String>,
    ) {
        *self.last_apply_result.lock().unwrap() = Some(TlsRedirectLastApplyResult {
            generation,
            state_hash,
            outcome,
            error,
        });
    }
}

fn state_hash(state: &TlsRedirectDesiredState) -> u64 {
    let mut hasher = DefaultHasher::new();
    state.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum NftCall {
        Probe(String),
        Delete(String),
        Apply(String),
    }

    #[derive(Default)]
    struct RecordingRunner {
        table_exists: AtomicBool,
        fail_apply: AtomicBool,
        calls: Mutex<Vec<NftCall>>,
    }

    impl RecordingRunner {
        fn with_table_exists(value: bool) -> Self {
            Self {
                table_exists: AtomicBool::new(value),
                fail_apply: AtomicBool::new(false),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn set_fail_apply(&self, value: bool) {
            self.fail_apply.store(value, Ordering::SeqCst);
        }

        fn take_calls(&self) -> Vec<NftCall> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }

    impl TlsRedirectCommandRunner for RecordingRunner {
        fn table_exists(&self, table_name: &str) -> Result<bool> {
            self.calls
                .lock()
                .unwrap()
                .push(NftCall::Probe(table_name.to_string()));
            Ok(self.table_exists.load(Ordering::SeqCst))
        }

        fn delete_table(&self, table_name: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(NftCall::Delete(table_name.to_string()));
            self.table_exists.store(false, Ordering::SeqCst);
            Ok(())
        }

        fn apply_script(&self, script: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(NftCall::Apply(script.to_string()));
            if self.fail_apply.load(Ordering::SeqCst) {
                bail!("injected nft apply failure");
            }
            self.table_exists.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn enabled_state(interface: &str) -> TlsRedirectDesiredState {
        TlsRedirectDesiredState::Enabled(TlsRedirectConfig::new(
            "0.0.0.0:9443".parse().unwrap(),
            vec![interface.to_string()],
            vec![443],
            vec![],
        ))
    }

    #[test]
    fn reconcile_enabled_installs_full_rendered_ruleset() {
        let runner = Arc::new(RecordingRunner::default());
        let manager = TlsRedirectManager::with_runner(runner.clone());

        let outcome = manager.reconcile(enabled_state("lan0")).unwrap();

        assert_eq!(outcome, TlsRedirectReconcileOutcome::Installed);
        let calls = runner.take_calls();
        assert!(matches!(calls[0], NftCall::Probe(_)));
        assert!(matches!(&calls[1], NftCall::Apply(script) if script.contains("iifname { \"lan0\" }")));
    }

    #[test]
    fn reconcile_unchanged_state_is_noop() {
        let runner = Arc::new(RecordingRunner::default());
        let manager = TlsRedirectManager::with_runner(runner.clone());

        manager.reconcile(enabled_state("lan0")).unwrap();
        runner.take_calls();

        let outcome = manager.reconcile(enabled_state("lan0")).unwrap();

        assert_eq!(outcome, TlsRedirectReconcileOutcome::Noop);
        assert!(runner.take_calls().is_empty());
    }

    #[test]
    fn reconcile_changed_state_replaces_table() {
        let runner = Arc::new(RecordingRunner::default());
        let manager = TlsRedirectManager::with_runner(runner.clone());

        manager.reconcile(enabled_state("lan0")).unwrap();
        runner.take_calls();

        let outcome = manager.reconcile(enabled_state("lan1")).unwrap();

        assert_eq!(outcome, TlsRedirectReconcileOutcome::Installed);
        let calls = runner.take_calls();
        assert!(matches!(calls[0], NftCall::Probe(_)));
        assert!(matches!(calls[1], NftCall::Delete(_)));
        assert!(matches!(&calls[2], NftCall::Apply(script) if script.contains("iifname { \"lan1\" }")));
    }

    #[test]
    fn reconcile_apply_failure_clears_applied_state_for_future_retries() {
        let runner = Arc::new(RecordingRunner::default());
        let manager = TlsRedirectManager::with_runner(runner.clone());

        manager.reconcile(enabled_state("lan0")).unwrap();
        runner.take_calls();

        runner.set_fail_apply(true);
        let err = manager.reconcile(enabled_state("lan1")).unwrap_err();
        assert!(err.to_string().contains("injected nft apply failure"));
        runner.take_calls();

        runner.set_fail_apply(false);
        let outcome = manager.reconcile(enabled_state("lan0")).unwrap();

        assert_eq!(outcome, TlsRedirectReconcileOutcome::Installed);
        let calls = runner.take_calls();
        assert!(matches!(calls[0], NftCall::Probe(_)));
        assert!(matches!(&calls[1], NftCall::Apply(script) if script.contains("iifname { \"lan0\" }")));
    }

    #[test]
    fn reconcile_empty_interfaces_uninstalls_and_errors() {
        let runner = Arc::new(RecordingRunner::with_table_exists(true));
        let manager = TlsRedirectManager::with_runner(runner.clone());
        let desired = TlsRedirectDesiredState::Enabled(TlsRedirectConfig::new(
            "0.0.0.0:9443".parse().unwrap(),
            vec![],
            vec![443],
            vec![],
        ));

        let err = manager.reconcile(desired).unwrap_err();

        assert!(err.to_string().contains("no capture interfaces"));
        assert_eq!(
            runner.take_calls(),
            vec![
                NftCall::Probe(TABLE_NAME.to_string()),
                NftCall::Delete(TABLE_NAME.to_string()),
            ]
        );
    }

    #[test]
    fn reconcile_disabled_uninstalls_existing_table() {
        let runner = Arc::new(RecordingRunner::with_table_exists(true));
        let manager = TlsRedirectManager::with_runner(runner.clone());

        let outcome = manager.reconcile(TlsRedirectDesiredState::Disabled).unwrap();

        assert_eq!(outcome, TlsRedirectReconcileOutcome::Uninstalled);
        assert_eq!(
            runner.take_calls(),
            vec![
                NftCall::Probe(TABLE_NAME.to_string()),
                NftCall::Delete(TABLE_NAME.to_string()),
            ]
        );
    }
}
