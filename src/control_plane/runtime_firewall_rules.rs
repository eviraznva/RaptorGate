use std::collections::HashMap;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeRule {
    pub id: String,
    pub name: String,
    pub zone_pair_id: String,
    pub priority: u32,
    pub content: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeZone {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeZoneInterface {
    pub id: String,
    pub zone_id: String,
    pub interface_name: String,
    pub vlan_id: Option<u32>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeZonePair {
    pub id: String,
    pub src_zone_id: String,
    pub dst_zone_id: String,
    pub default_policy: i32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeNatRule {
    pub id: String,
    pub nat_type: i32,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u32>,
    pub dst_port: Option<u32>,
    pub translated_ip: String,
    pub translated_port: Option<u32>,
    pub priority: u32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeDnsBlacklistEntry {
    pub id: String,
    pub domain: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeSslBypassEntry {
    pub id: String,
    pub domain: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeIpsSignature {
    pub id: String,
    pub name: String,
    pub category: String,
    pub pattern: String,
    pub severity: i32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeMlModel {
    pub id: String,
    pub name: String,
    pub artifact_path: String,
    pub checksum: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeFirewallCertificate {
    pub id: String,
    pub cert_type: i32,
    pub common_name: String,
    pub fingerprint: String,
    pub certificate_pem: String,
    pub private_key_ref: String,
    pub expires_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeUserGroup {
    pub id: String,
    pub name: String,
    pub source: i32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeIdentityUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub source: i32,
    pub external_id: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeUserGroupMember {
    pub id: String,
    pub group_id: String,
    pub identity_user_id: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeIdentitySession {
    pub id: String,
    pub identity_user_id: String,
    pub radius_username: String,
    pub mac_address: String,
    pub ip_address: String,
    pub nas_ip: String,
    pub called_station_id: String,
    pub authenticated_at_unix: Option<i64>,
    pub expires_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeFirewallRulesIndexes {
    pub zones_by_id: HashMap<String, RuntimeZone>,
    pub zone_pairs_by_id: HashMap<String, RuntimeZonePair>,
    pub zone_interfaces_by_name: HashMap<String, RuntimeZoneInterface>,
    pub rules_by_id: HashMap<String, RuntimeRule>,
    pub nat_rules_by_id: HashMap<String, RuntimeNatRule>,
    pub dns_blacklist_by_domain: HashMap<String, RuntimeDnsBlacklistEntry>,
    pub ssl_bypass_by_domain: HashMap<String, RuntimeSslBypassEntry>,
    pub ips_signatures_by_id: HashMap<String, RuntimeIpsSignature>,
    pub identity_users_by_id: HashMap<String, RuntimeIdentityUser>,
    pub user_groups_by_id: HashMap<String, RuntimeUserGroup>,
    pub sessions_by_ip: HashMap<String, RuntimeIdentitySession>,
    pub user_groups_by_user_id: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeFirewallRulesMeta {
    pub config_version: u64,
    pub bundle_checksum: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeFirewallRules {
    pub meta: RuntimeFirewallRulesMeta,
    pub rules: Vec<RuntimeRule>,
    pub zones: Vec<RuntimeZone>,
    pub zone_interfaces: Vec<RuntimeZoneInterface>,
    pub zone_pairs: Vec<RuntimeZonePair>,
    pub nat_rules: Vec<RuntimeNatRule>,
    pub dns_blacklist: Vec<RuntimeDnsBlacklistEntry>,
    pub ssl_bypass_list: Vec<RuntimeSslBypassEntry>,
    pub ips_signatures: Vec<RuntimeIpsSignature>,
    pub ml_model: Option<RuntimeMlModel>,
    pub firewall_certificates: Vec<RuntimeFirewallCertificate>,
    pub identity_user_groups: Vec<RuntimeUserGroup>,
    pub identity_users: Vec<RuntimeIdentityUser>,
    pub identity_group_members: Vec<RuntimeUserGroupMember>,
    pub identity_sessions: Vec<RuntimeIdentitySession>,
    pub indexes: RuntimeFirewallRulesIndexes,
}

impl RuntimeFirewallRules {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn config_version(&self) -> u64 {
        self.meta.config_version
    }
}
