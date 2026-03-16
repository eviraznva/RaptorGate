use crate::control_plane::backend_api::proto::raptorgate::config::ConfigSectionVersions;

#[derive(Debug, thiserror::Error)]
pub enum DeltaError {
    #[error("config delta is missing current_versions")]
    MissingCurrentVersions,
}

pub(crate) struct ChangedSections {
    pub rules: bool,
    pub zones: bool,
    pub zone_interfaces: bool,
    pub zone_pairs: bool,
    pub nat_rules: bool,
    pub dns_blacklist: bool,
    pub ssl_bypass_list: bool,
    pub ips_signatures: bool,
    pub ml_model: bool,
    pub certificates: bool,
    pub identity: bool,
}

impl ChangedSections {
    pub fn from_versions(
        previous: &ConfigSectionVersions,
        current: &ConfigSectionVersions,
    ) -> Self {
        Self {
            rules: current.rules != previous.rules,
            zones: current.zones != previous.zones,
            zone_interfaces: current.zone_interfaces != previous.zone_interfaces,
            zone_pairs: current.zone_pairs != previous.zone_pairs,
            nat_rules: current.nat_rules != previous.nat_rules,
            dns_blacklist: current.dns_blacklist != previous.dns_blacklist,
            ssl_bypass_list: current.ssl_bypass_list != previous.ssl_bypass_list,
            ips_signatures: current.ips_signatures != previous.ips_signatures,
            ml_model: current.ml_model != previous.ml_model,
            certificates: current.certificates != previous.certificates,
            identity: current.identity != previous.identity,
        }
    }
}
