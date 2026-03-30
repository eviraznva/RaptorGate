use crate::control_plane::backend_api::proto::raptorgate::config::{
    ConfigResponse, ConfigSectionVersions, DnsBlacklistEntry, DnsBlacklistSet, FirewallCertificate,
    FirewallCertificateSet, IdentityBundle, IpsSignature, IpsSignatureSet, MlModel, NatRule,
    NatRuleSet, Rule, RuleSet, SslBypassEntry, SslBypassSet, Zone, ZoneInterface, ZoneInterfaceSet,
    ZonePair, ZonePairSet, ZoneSet,
};
use crate::control_plane::config::delta::{ChangedSections, DeltaError};

#[derive(Clone)]
pub struct ActiveConfig {
    pub version: u64,
    pub bundle_checksum: String,
    pub section_versions: ConfigSectionVersions,
    pub rules: Vec<Rule>,
    pub zones: Vec<Zone>,
    pub zone_interfaces: Vec<ZoneInterface>,
    pub zone_pairs: Vec<ZonePair>,
    pub nat_rules: Vec<NatRule>,
    pub dns_blacklist: Vec<DnsBlacklistEntry>,
    pub ssl_bypass_list: Vec<SslBypassEntry>,
    pub ips_signatures: Vec<IpsSignature>,
    pub ml_model: Option<MlModel>,
    pub firewall_certificates: Vec<FirewallCertificate>,
    pub identity: Option<IdentityBundle>,
}

impl ActiveConfig {
    pub fn from_response(resp: ConfigResponse) -> Self {
        Self {
            version: resp.config_version,
            bundle_checksum: resp.bundle_checksum,
            section_versions: resp.current_versions.unwrap_or_default(),
            rules: resp.rules.map(|s| s.items).unwrap_or_default(),
            zones: resp.zones.map(|s| s.items).unwrap_or_default(),
            zone_interfaces: resp.zone_interfaces.map(|s| s.items).unwrap_or_default(),
            zone_pairs: resp.zone_pairs.map(|s| s.items).unwrap_or_default(),
            nat_rules: resp.nat_rules.map(|s| s.items).unwrap_or_default(),
            dns_blacklist: resp.dns_blacklist.map(|s| s.items).unwrap_or_default(),
            ssl_bypass_list: resp.ssl_bypass_list.map(|s| s.items).unwrap_or_default(),
            ips_signatures: resp.ips_signatures.map(|s| s.items).unwrap_or_default(),
            ml_model: resp.ml_model,
            firewall_certificates: resp
                .firewall_certificates
                .map(|s| s.items)
                .unwrap_or_default(),
            identity: resp.identity,
        }
    }

    pub fn to_config_response(&self) -> ConfigResponse {
        ConfigResponse {
            config_version: self.version,
            bundle_checksum: self.bundle_checksum.clone(),
            correlation_id: String::new(),
            configuration_changed: true,
            current_versions: Some(self.section_versions.clone()),
            rules: Some(RuleSet {
                version: self.section_versions.rules,
                checksum: String::new(),
                items: self.rules.clone(),
            }),
            zones: Some(ZoneSet {
                version: self.section_versions.zones,
                items: self.zones.clone(),
            }),
            zone_interfaces: Some(ZoneInterfaceSet {
                version: self.section_versions.zone_interfaces,
                items: self.zone_interfaces.clone(),
            }),
            zone_pairs: Some(ZonePairSet {
                version: self.section_versions.zone_pairs,
                items: self.zone_pairs.clone(),
            }),
            nat_rules: Some(NatRuleSet {
                version: self.section_versions.nat_rules,
                items: self.nat_rules.clone(),
            }),
            dns_blacklist: Some(DnsBlacklistSet {
                version: self.section_versions.dns_blacklist,
                items: self.dns_blacklist.clone(),
            }),
            ssl_bypass_list: Some(SslBypassSet {
                version: self.section_versions.ssl_bypass_list,
                items: self.ssl_bypass_list.clone(),
            }),
            ips_signatures: Some(IpsSignatureSet {
                version: self.section_versions.ips_signatures,
                items: self.ips_signatures.clone(),
            }),
            ml_model: self.ml_model.clone(),
            firewall_certificates: Some(FirewallCertificateSet {
                version: self.section_versions.certificates,
                items: self.firewall_certificates.clone(),
            }),
            identity: self.identity.clone(),
        }
    }

    pub fn apply_delta(&self, resp: ConfigResponse) -> Result<Self, DeltaError> {
        let current_versions = resp
            .current_versions
            .clone()
            .ok_or(DeltaError::MissingCurrentVersions)?;
        let changed = ChangedSections::from_versions(&self.section_versions, &current_versions);

        Ok(Self {
            version: resp.config_version,
            bundle_checksum: resp.bundle_checksum,
            section_versions: current_versions,
            rules: if changed.rules {
                resp.rules.map(|s| s.items).unwrap_or_default()
            } else {
                self.rules.clone()
            },
            zones: if changed.zones {
                resp.zones.map(|s| s.items).unwrap_or_default()
            } else {
                self.zones.clone()
            },
            zone_interfaces: if changed.zone_interfaces {
                resp.zone_interfaces.map(|s| s.items).unwrap_or_default()
            } else {
                self.zone_interfaces.clone()
            },
            zone_pairs: if changed.zone_pairs {
                resp.zone_pairs.map(|s| s.items).unwrap_or_default()
            } else {
                self.zone_pairs.clone()
            },
            nat_rules: if changed.nat_rules {
                resp.nat_rules.map(|s| s.items).unwrap_or_default()
            } else {
                self.nat_rules.clone()
            },
            dns_blacklist: if changed.dns_blacklist {
                resp.dns_blacklist.map(|s| s.items).unwrap_or_default()
            } else {
                self.dns_blacklist.clone()
            },
            ssl_bypass_list: if changed.ssl_bypass_list {
                resp.ssl_bypass_list.map(|s| s.items).unwrap_or_default()
            } else {
                self.ssl_bypass_list.clone()
            },
            ips_signatures: if changed.ips_signatures {
                resp.ips_signatures.map(|s| s.items).unwrap_or_default()
            } else {
                self.ips_signatures.clone()
            },
            ml_model: if changed.ml_model {
                resp.ml_model
            } else {
                self.ml_model.clone()
            },
            firewall_certificates: if changed.certificates {
                resp.firewall_certificates
                    .map(|s| s.items)
                    .unwrap_or_default()
            } else {
                self.firewall_certificates.clone()
            },
            identity: if changed.identity {
                resp.identity
            } else {
                self.identity.clone()
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::ser::State::Empty;

    fn base_versions() -> ConfigSectionVersions {
        ConfigSectionVersions {
            rules: 1,
            zones: 1,
            zone_interfaces: 1,
            zone_pairs: 1,
            nat_rules: 1,
            dns_blacklist: 1,
            ssl_bypass_list: 1,
            ips_signatures: 1,
            ml_model: 1,
            certificates: 1,
            identity: 1,
        }
    }

    fn sample_rule(name: &str) -> Rule {
        Rule {
            id: name.into(),
            name: name.into(),
            zone_pair_id: "zp-1".into(),
            priority: 1,
            content: "allow".into(),
        }
    }

    fn base_config() -> ActiveConfig {
        ActiveConfig {
            version: 1,
            bundle_checksum: "old".into(),
            section_versions: base_versions(),
            rules: vec![sample_rule("rule-1")],
            zones: Vec::new(),
            zone_interfaces: Vec::new(),
            zone_pairs: Vec::new(),
            nat_rules: vec![NatRule::default()],
            dns_blacklist: Vec::new(),
            ssl_bypass_list: Vec::new(),
            ips_signatures: Vec::new(),
            ml_model: Some(MlModel {
                version: 0,
                id: "model-1".into(),
                name: "model".into(),
                artifact_path: "/tmp/model.onnx".into(),
                checksum: "abc".into(),
            }),
            firewall_certificates: Vec::new(),
            identity: Some(IdentityBundle::default()),
        }
    }

    #[test]
    fn apply_delta_clears_repeated_section_when_version_changes_to_empty() {
        let base = base_config();
        let mut next_versions = base_versions();
        next_versions.nat_rules = 2;

        let next = base
            .apply_delta(ConfigResponse {
                config_version: 2,
                bundle_checksum: "new".into(),
                correlation_id: "corr".into(),
                configuration_changed: true,
                current_versions: Some(next_versions),
                nat_rules: None,
                ..Default::default()
            })
            .expect("delta should apply");

        assert!(next.nat_rules.is_empty());
    }

    #[test]
    fn apply_delta_clears_optional_section_when_version_changes_to_none() {
        let base = base_config();
        let mut next_versions = base_versions();
        next_versions.ml_model = 2;

        let next = base
            .apply_delta(ConfigResponse {
                config_version: 2,
                bundle_checksum: "new".into(),
                correlation_id: "corr".into(),
                configuration_changed: true,
                current_versions: Some(next_versions),
                ml_model: None,
                ..Default::default()
            })
            .expect("delta should apply");

        assert!(next.ml_model.is_none());
    }
}
