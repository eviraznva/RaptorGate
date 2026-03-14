use std::fs;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::control_plane::runtime_firewall_rules::RuntimeFirewallRules;

#[derive(Debug, Clone)]
pub struct SnapshotStore {
    path: PathBuf,
}

impl SnapshotStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn load(&self) -> Result<Option<RuntimeFirewallRules>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.path)
            .with_context(|| format!("Failed to read snapshot file {}", self.path.display()))?;

        let parsed: RuntimeFirewallRules =
            serde_json::from_str(&content).context("Failed to deserialize runtime snapshot")?;

        Ok(Some(parsed))
    }

    pub fn save(&self, snapshot: &RuntimeFirewallRules) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_vec_pretty(snapshot)
            .context("Failed to serialize runtime snapshot")?;

        fs::write(&self.path, json)
            .with_context(|| format!("Failed to write snapshot {}", self.path.display()))?;

        Ok(())
    }
}