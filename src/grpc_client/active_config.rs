use crate::grpc_client::proto_types::raptorgate::config::{
    ConfigResponse, ConfigSectionVersions, DnsBlacklistEntry, FirewallCertificate,
    IdentityBundle, IpsSignature, MlModel, NatRule, Rule, SslBypassEntry,
    Zone, ZoneInterface, ZonePair,
};

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
    
    pub fn merge_delta(&mut self, resp: ConfigResponse) {
        self.version = resp.config_version;
        self.bundle_checksum = resp.bundle_checksum;
        if let Some(sv) = resp.current_versions       { self.section_versions = sv; }
        if !resp.rules.is_empty()                     { self.rules = resp.rules; }
        if !resp.zones.is_empty()                     { self.zones = resp.zones; }
        if !resp.zone_interfaces.is_empty()           { self.zone_interfaces = resp.zone_interfaces; }
        if !resp.zone_pairs.is_empty()                { self.zone_pairs = resp.zone_pairs; }
        if !resp.nat_rules.is_empty()                 { self.nat_rules = resp.nat_rules; }
        if !resp.dns_blacklist.is_empty()             { self.dns_blacklist = resp.dns_blacklist; }
        if !resp.ssl_bypass_list.is_empty()           { self.ssl_bypass_list = resp.ssl_bypass_list; }
        if !resp.ips_signatures.is_empty()            { self.ips_signatures = resp.ips_signatures; }
        if resp.ml_model.is_some()                    { self.ml_model = resp.ml_model; }
        if !resp.firewall_certificates.is_empty()     { self.firewall_certificates = resp.firewall_certificates; }
        if resp.identity.is_some()                    { self.identity = resp.identity; }
    }
}
