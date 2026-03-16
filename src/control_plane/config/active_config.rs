use crate::control_plane::backend_api::proto::raptorgate::config::{
    ConfigResponse, ConfigSectionVersions, DnsBlacklistEntry, FirewallCertificate, IdentityBundle,
    IpsSignature, MlModel, NatRule, Rule, SslBypassEntry, Zone, ZoneInterface, ZonePair,
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
            rules: resp.rules,
            zones: resp.zones,
            zone_interfaces: resp.zone_interfaces,
            zone_pairs: resp.zone_pairs,
            nat_rules: resp.nat_rules,
            dns_blacklist: resp.dns_blacklist,
            ssl_bypass_list: resp.ssl_bypass_list,
            ips_signatures: resp.ips_signatures,
            ml_model: resp.ml_model,
            firewall_certificates: resp.firewall_certificates,
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
            rules: self.rules.clone(),
            zones: self.zones.clone(),
            zone_interfaces: self.zone_interfaces.clone(),
            zone_pairs: self.zone_pairs.clone(),
            nat_rules: self.nat_rules.clone(),
            dns_blacklist: self.dns_blacklist.clone(),
            ssl_bypass_list: self.ssl_bypass_list.clone(),
            ips_signatures: self.ips_signatures.clone(),
            ml_model: self.ml_model.clone(),
            firewall_certificates: self.firewall_certificates.clone(),
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
                resp.rules
            } else {
                self.rules.clone()
            },
            zones: if changed.zones {
                resp.zones
            } else {
                self.zones.clone()
            },
            zone_interfaces: if changed.zone_interfaces {
                resp.zone_interfaces
            } else {
                self.zone_interfaces.clone()
            },
            zone_pairs: if changed.zone_pairs {
                resp.zone_pairs
            } else {
                self.zone_pairs.clone()
            },
            nat_rules: if changed.nat_rules {
                resp.nat_rules
            } else {
                self.nat_rules.clone()
            },
            dns_blacklist: if changed.dns_blacklist {
                resp.dns_blacklist
            } else {
                self.dns_blacklist.clone()
            },
            ssl_bypass_list: if changed.ssl_bypass_list {
                resp.ssl_bypass_list
            } else {
                self.ssl_bypass_list.clone()
            },
            ips_signatures: if changed.ips_signatures {
                resp.ips_signatures
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
                nat_rules: Vec::new(),
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
