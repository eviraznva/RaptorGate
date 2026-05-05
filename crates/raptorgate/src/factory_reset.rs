use crate::config::AppConfig;

#[derive(Debug, Clone, Copy)]
pub struct FactoryResetOptions {
    pub clear_pki: bool,
    pub clear_server_keys: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FactoryResetReport {
    pub safe_state_applied: bool,
    pub removed_server_keys: u64,
    pub removed_server_key_files: u64,
    pub removed_ca_files: u64,
}

pub fn safe_app_config(current: &AppConfig) -> AppConfig {
    let mut config = current.clone();
    config.ssl_inspection_enabled = false;
    config.ssl_bypass_domains.clear();
    config.block_tls_on_undeclared_ports = false;
    config
}
