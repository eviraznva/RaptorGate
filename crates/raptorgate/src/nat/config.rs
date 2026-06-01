use ipnet::IpNet;
use std::sync::Arc;
use std::net::IpAddr;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::proto::{common, config};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatConfig {
    #[serde(default)]
    pub rules: Vec<NatConfigRule>,
}

impl NatConfig {
    pub fn from_proto_rules(rules: &[config::NatRule]) -> Result<Self> {
        let mut items = Vec::with_capacity(rules.len());

        for rule in rules {
            items.push(NatConfigRule::from_runtime(&NatRule::try_from_proto(rule.clone())?));
        }

        Ok(Self { rules: items })
    }

    pub fn to_runtime_rules(&self) -> Result<Option<Arc<NatRules>>> {
        if self.rules.is_empty() {
            return Ok(None);
        }

        let mut runtime_rules = Vec::with_capacity(self.rules.len());

        for rule in &self.rules {
            runtime_rules.push(rule.to_runtime_rule()?);
        }

        Ok(Some(Arc::new(NatRules::new(runtime_rules))))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommonMatchers {
    #[serde(default)]
    pub in_interface: Option<String>,
    #[serde(default)]
    pub out_interface: Option<String>,
    #[serde(default)]
    pub in_zone: Option<String>,
    #[serde(default)]
    pub out_zone: Option<String>,
    #[serde(default = "default_protocol_all")]
    pub protocol: NatConfigProtocol,
    #[serde(default)]
    pub match_src_port_min: Option<u16>,
    #[serde(default)]
    pub match_src_port_max: Option<u16>,
    #[serde(default)]
    pub match_dst_port_min: Option<u16>,
    #[serde(default)]
    pub match_dst_port_max: Option<u16>,
}

fn default_protocol_all() -> NatConfigProtocol { NatConfigProtocol::All }

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NatConfigProtocol {
    #[default]
    All,
    Tcp,
    Udp,
    Icmp,
}

impl NatConfigProtocol {
    fn to_runtime(self) -> NatProtocol {
        match self {
            Self::All  => NatProtocol::All,
            Self::Tcp  => NatProtocol::Tcp,
            Self::Udp  => NatProtocol::Udp,
            Self::Icmp => NatProtocol::Icmp,
        }
    }
    fn from_runtime(p: NatProtocol) -> Self {
        match p {
            NatProtocol::All  => Self::All,
            NatProtocol::Tcp  => Self::Tcp,
            NatProtocol::Udp  => Self::Udp,
            NatProtocol::Icmp => Self::Icmp,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum NatConfigRule {
    Snat {
        id: String,
        priority: u32,
        #[serde(default)]
        common: CommonMatchers,
        src_cidr: String,
        translated_ip: String,
        #[serde(default)]
        src_port_min: Option<u16>,
        #[serde(default)]
        src_port_max: Option<u16>,
    },
    Dnat {
        id: String,
        priority: u32,
        #[serde(default)]
        common: CommonMatchers,
        dst_cidr: String,
        translated_ip: String,
        #[serde(default)]
        translated_port: Option<u16>,
    },
    Pat {
        id: String,
        priority: u32,
        #[serde(default)]
        common: CommonMatchers,
        dst_ip: String,
        dst_port: u16,
        translated_ip: String,
        translated_port: u16,
    },
    Masquerade {
        id: String,
        priority: u32,
        common: CommonMatchers,
        #[serde(default)]
        src_cidr: Option<String>,
        #[serde(default)]
        src_port_min: Option<u16>,
        #[serde(default)]
        src_port_max: Option<u16>,
    },
}

impl NatConfigRule {
    pub fn to_runtime_rule(&self) -> Result<NatRule> {
        match self {
            Self::Snat { 
                id, 
                priority, 
                common, 
                src_cidr, 
                translated_ip, 
                src_port_min, 
                src_port_max } => {
                
                let action = NatAction::Snat {
                    src_cidr: parse_ipnet(src_cidr, "snat.src_cidr")?,
                    translated_ip: translated_ip.parse::<IpAddr>().with_context(|| format!("invalid snat.translated_ip: {translated_ip}"))?,
                    src_port_range: pair_ports(*src_port_min, *src_port_max, "snat")?,
                };
                
                build_rule(id, *priority, common, action)
            },

            Self::Dnat { id, priority, common, dst_cidr, translated_ip, translated_port } => {
                let action = NatAction::Dnat {
                    dst_cidr: parse_ipnet(dst_cidr, "dnat.dst_cidr")?,
                    translated_ip: translated_ip.parse::<IpAddr>().with_context(|| format!("invalid dnat.translated_ip: {translated_ip}"))?,
                    translated_port: *translated_port,
                };

                build_rule(id, *priority, common, action)
            },
            
            Self::Pat { id, priority, common, dst_ip, dst_port, translated_ip, translated_port } => {
                let action = NatAction::Pat {
                    dst_ip: dst_ip.parse::<IpAddr>().with_context(|| format!("invalid pat.dst_ip: {dst_ip}"))?,
                    dst_port: *dst_port,
                    translated_ip: translated_ip.parse::<IpAddr>().with_context(|| format!("invalid pat.translated_ip: {translated_ip}"))?,
                    translated_port: *translated_port,
                };
                
                build_rule(id, *priority, common, action)
            },
            
            Self::Masquerade { id, priority, common, src_cidr, src_port_min, src_port_max } => {
                if normalize_optional_matcher(common.out_interface.clone()).is_none() {
                    bail!("masquerade rule '{id}' requires common.out_interface");
                }
                
                let action = NatAction::Masquerade {
                    src_cidr: src_cidr.as_deref().map(|s| parse_ipnet(s, "masquerade.src_cidr")).transpose()?,
                    src_port_range: pair_ports(*src_port_min, *src_port_max, "masquerade")?,
                };
                
                build_rule(id, *priority, common, action)
            }
        }
    }

    pub fn from_runtime(rule: &NatRule) -> Self {
        let common = CommonMatchers {
            in_interface: rule.in_interface().map(String::from),
            out_interface: rule.out_interface().map(String::from),
            in_zone: rule.in_zone().map(String::from),
            out_zone: rule.out_zone().map(String::from),
            protocol: NatConfigProtocol::from_runtime(rule.protocol()),
            match_src_port_min: rule.match_src_port_range().map(|(lo, _)| lo),
            match_src_port_max: rule.match_src_port_range().map(|(_, hi)| hi),
            match_dst_port_min: rule.match_dst_port_range().map(|(lo, _)| lo),
            match_dst_port_max: rule.match_dst_port_range().map(|(_, hi)| hi),
        };
        
        match rule.action() {
            NatAction::Snat { src_cidr, translated_ip, src_port_range } => Self::Snat {
                id: rule.id().to_string(),
                priority: rule.priority(),
                common,
                src_cidr: src_cidr.to_string(),
                translated_ip: translated_ip.to_string(),
                src_port_min: src_port_range.map(|(lo, _)| lo),
                src_port_max: src_port_range.map(|(_, hi)| hi),
            },

            NatAction::Dnat { dst_cidr, translated_ip, translated_port } => Self::Dnat {
                id: rule.id().to_string(),
                priority: rule.priority(),
                common,
                dst_cidr: dst_cidr.to_string(),
                translated_ip: translated_ip.to_string(),
                translated_port: *translated_port,
            },
            
            NatAction::Pat { dst_ip, dst_port, translated_ip, translated_port } => Self::Pat {
                id: rule.id().to_string(),
                priority: rule.priority(),
                common,
                dst_ip: dst_ip.to_string(),
                dst_port: *dst_port,
                translated_ip: translated_ip.to_string(),
                translated_port: *translated_port,
            },
            
            NatAction::Masquerade { src_cidr, src_port_range } => Self::Masquerade {
                id: rule.id().to_string(),
                priority: rule.priority(),
                common,
                src_cidr: src_cidr.map(|n| n.to_string()),
                src_port_min: src_port_range.map(|(lo, _)| lo),
                src_port_max: src_port_range.map(|(_, hi)| hi),
            },
        }
    }
}

fn build_rule(id: &str, priority: u32, common: &CommonMatchers, action: NatAction) -> Result<NatRule> {
    Ok(NatRule::new(
        id.to_string(),
        priority,
        normalize_optional_matcher(common.in_interface.clone()),
        normalize_optional_matcher(common.out_interface.clone()),
        normalize_optional_matcher(common.in_zone.clone()),
        normalize_optional_matcher(common.out_zone.clone()),
        common.protocol.to_runtime(),
        pair_ports(common.match_src_port_min, common.match_src_port_max, "match_src_port")?,
        pair_ports(common.match_dst_port_min, common.match_dst_port_max, "match_dst_port")?,
        action,
    ))
}

fn normalize_optional_matcher(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();

        if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
    })
}

fn pair_ports(min: Option<u16>, max: Option<u16>, scope: &str) -> Result<Option<(u16, u16)>> {
    match (min, max) {
        (None, None) => Ok(None),
        (Some(lo), Some(hi)) if lo > 0 && hi >= lo => Ok(Some((lo, hi))),
        (Some(_), Some(_)) => bail!("{scope}: invalid port range (lo>hi or zero)"),
        _ => bail!("{scope}: src_port_min and src_port_max must both be set or both empty"),
    }
}

fn parse_ipnet(value: &str, field: &str) -> Result<IpNet> {
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(net);
    }
    
    let addr = value.parse::<IpAddr>().with_context(|| format!("invalid {field}: {value}"))?;
    
    Ok(IpNet::from(addr))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatProtocol {
    All,
    Tcp,
    Udp,
    Icmp,
}

impl NatProtocol {
    fn from_proto(v: i32) -> Result<Self> {
        match common::NatProtocol::try_from(v).context("invalid nat protocol")? {
            common::NatProtocol::All  => Ok(Self::All),
            common::NatProtocol::Tcp  => Ok(Self::Tcp),
            common::NatProtocol::Udp  => Ok(Self::Udp),
            common::NatProtocol::Icmp => Ok(Self::Icmp),
        }
    }

    fn to_proto(self) -> common::NatProtocol {
        match self {
            Self::All  => common::NatProtocol::All,
            Self::Tcp  => common::NatProtocol::Tcp,
            Self::Udp  => common::NatProtocol::Udp,
            Self::Icmp => common::NatProtocol::Icmp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatAction {
    Snat {
        src_cidr: IpNet,
        translated_ip: IpAddr,
        src_port_range: Option<(u16, u16)>,
    },
    Dnat {
        dst_cidr: IpNet,
        translated_ip: IpAddr,
        translated_port: Option<u16>,
    },
    Pat {
        dst_ip: IpAddr,
        dst_port: u16,
        translated_ip: IpAddr,
        translated_port: u16,
    },
    Masquerade {
        src_cidr: Option<IpNet>,
        src_port_range: Option<(u16, u16)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatRule {
    id: String,
    priority: u32,
    in_interface: Option<String>,
    out_interface: Option<String>,
    in_zone: Option<String>,
    out_zone: Option<String>,
    protocol: NatProtocol,
    match_src_port_range: Option<(u16, u16)>,
    match_dst_port_range: Option<(u16, u16)>,
    action: NatAction,
}

impl NatRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        priority: u32,
        in_interface: Option<String>,
        out_interface: Option<String>,
        in_zone: Option<String>,
        out_zone: Option<String>,
        protocol: NatProtocol,
        match_src_port_range: Option<(u16, u16)>,
        match_dst_port_range: Option<(u16, u16)>,
        action: NatAction,
    ) -> Self {
        Self {
            id, priority, in_interface, out_interface, in_zone, out_zone,
            protocol, match_src_port_range, match_dst_port_range, action,
        }
    }

    pub fn try_from_proto(value: config::NatRule) -> Result<Self> {
        let action_proto = value.action.context("nat rule has no action")?;
        let in_interface = normalize_optional_matcher(value.in_interface);
        let out_interface = normalize_optional_matcher(value.out_interface);
        let in_zone = normalize_optional_matcher(value.in_zone);
        let out_zone = normalize_optional_matcher(value.out_zone);

        let action = match action_proto {
            config::nat_rule::Action::Snat(s) => NatAction::Snat {
                src_cidr: parse_required_net(&s.src_cidr, "snat.src_cidr")?,
                translated_ip: parse_required_ip(&s.translated_ip, "snat.translated_ip")?,
                src_port_range: parse_port_range(s.src_port_min, s.src_port_max, "snat")?,
            },

            config::nat_rule::Action::Dnat(d) => NatAction::Dnat {
                dst_cidr: parse_required_net(&d.dst_cidr, "dnat.dst_cidr")?,
                translated_ip: parse_required_ip(&d.translated_ip, "dnat.translated_ip")?,
                translated_port: d.translated_port.map(|p| parse_required_port(p, "dnat.translated_port")).transpose()?,
            },

            config::nat_rule::Action::Pat(p) => NatAction::Pat {
                dst_ip: parse_required_ip(&p.dst_ip, "pat.dst_ip")?,
                dst_port: parse_required_port(p.dst_port, "pat.dst_port")?,
                translated_ip: parse_required_ip(&p.translated_ip, "pat.translated_ip")?,
                translated_port: parse_required_port(p.translated_port, "pat.translated_port")?,
            },

            config::nat_rule::Action::Masquerade(m) => {
                if out_interface.is_none() {
                    bail!("masquerade requires out_interface");
                }

                NatAction::Masquerade {
                    src_cidr: m.src_cidr.as_deref().map(|s| parse_required_net(s, "masquerade.src_cidr")).transpose()?,
                    src_port_range: parse_port_range(m.src_port_min, m.src_port_max, "masquerade")?,
                }
            }
        };

        Ok(Self::new(
            value.id,
            value.priority,
            in_interface,
            out_interface,
            in_zone,
            out_zone,
            NatProtocol::from_proto(value.protocol)?,
            parse_port_range(value.match_src_port_min, value.match_src_port_max, "match_src_port")?,
            parse_port_range(value.match_dst_port_min, value.match_dst_port_max, "match_dst_port")?,
            action,
        ))
    }

    pub fn into_proto(&self) -> config::NatRule {
        let action = match &self.action {
            NatAction::Snat { src_cidr, translated_ip, src_port_range } => {
                config::nat_rule::Action::Snat(config::SnatRule {
                    src_cidr: src_cidr.to_string(),
                    translated_ip: translated_ip.to_string(),
                    src_port_min: src_port_range.map(|(lo, _)| u32::from(lo)),
                    src_port_max: src_port_range.map(|(_, hi)| u32::from(hi)),
                })
            },

            NatAction::Dnat { dst_cidr, translated_ip, translated_port } => {
                config::nat_rule::Action::Dnat(config::DnatRule {
                    dst_cidr: dst_cidr.to_string(),
                    translated_ip: translated_ip.to_string(),
                    translated_port: translated_port.map(|p| u32::from(p)),
                })
            },

            NatAction::Pat { dst_ip, dst_port, translated_ip, translated_port } => {
                config::nat_rule::Action::Pat(config::PatRule {
                    dst_ip: dst_ip.to_string(),
                    dst_port: u32::from(*dst_port),
                    translated_ip: translated_ip.to_string(),
                    translated_port: u32::from(*translated_port),
                })
            },

            NatAction::Masquerade { src_cidr, src_port_range } => {
                config::nat_rule::Action::Masquerade(config::MasqueradeRule {
                    src_cidr: src_cidr.map(|n| n.to_string()),
                    src_port_min: src_port_range.map(|(lo, _)| u32::from(lo)),
                    src_port_max: src_port_range.map(|(_, hi)| u32::from(hi)),
                })
            }
        };

        config::NatRule {
            id: self.id.clone(),
            priority: self.priority,
            in_interface: self.in_interface.clone(),
            out_interface: self.out_interface.clone(),
            in_zone: self.in_zone.clone(),
            out_zone: self.out_zone.clone(),
            protocol: self.protocol.to_proto() as i32,
            match_src_port_min: self.match_src_port_range.map(|(lo, _)| u32::from(lo)),
            match_src_port_max: self.match_src_port_range.map(|(_, hi)| u32::from(hi)),
            match_dst_port_min: self.match_dst_port_range.map(|(lo, _)| u32::from(lo)),
            match_dst_port_max: self.match_dst_port_range.map(|(_, hi)| u32::from(hi)),
            action: Some(action),
        }
    }

    pub fn id(&self) -> &str { &self.id }
    pub fn priority(&self) -> u32 { self.priority }
    pub fn in_interface(&self) -> Option<&str> { self.in_interface.as_deref() }
    pub fn out_interface(&self) -> Option<&str> { self.out_interface.as_deref() }
    pub fn in_zone(&self) -> Option<&str> { self.in_zone.as_deref() }
    pub fn out_zone(&self) -> Option<&str> { self.out_zone.as_deref() }
    pub fn protocol(&self) -> NatProtocol { self.protocol }
    pub fn match_src_port_range(&self) -> Option<(u16, u16)> { self.match_src_port_range }
    pub fn match_dst_port_range(&self) -> Option<(u16, u16)> { self.match_dst_port_range }
    pub fn action(&self) -> &NatAction { &self.action }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NatRules {
    rules: Vec<NatRule>,
}

impl NatRules {
    pub fn new(mut rules: Vec<NatRule>) -> Self {
        rules.sort_by_key(NatRule::priority);
        
        Self { rules }
    }

    pub fn rules(&self) -> &[NatRule] { &self.rules }

    pub fn is_empty(&self) -> bool { self.rules.is_empty() }

    pub fn try_from_proto(value: config::NatRuleSet) -> Result<Self> {
        value.items.into_iter().map(NatRule::try_from_proto).collect::<Result<Vec<_>>>().map(Self::new)
    }

    pub fn into_proto(&self) -> config::NatRuleSet {
        config::NatRuleSet {
            items: self.rules.iter().map(NatRule::into_proto).collect(),
        }
    }
}

fn parse_required_net(value: &str, field: &str) -> Result<IpNet> {
    if value.is_empty() {
        bail!("{field} is required");
    }

    if value.contains('/') {
        return value.parse::<IpNet>().with_context(|| format!("invalid {field}"));
    }

    let ip = value.parse::<IpAddr>().with_context(|| format!("invalid {field}"))?;

    let prefix = if ip.is_ipv4() { 32 } else { 128 };

    IpNet::new(ip, prefix).with_context(|| format!("invalid {field}"))
}

fn parse_required_ip(value: &str, field: &str) -> Result<IpAddr> {
    if value.is_empty() {
        bail!("{field} is required");
    }

    value.parse::<IpAddr>().with_context(|| format!("invalid {field}"))
}

fn parse_required_port(value: u32, field: &str) -> Result<u16> {
    if value == 0 {
        bail!("{field} must be between 1 and 65535");
    }

    u16::try_from(value).with_context(|| format!("{field} must be between 1 and 65535"))
}

fn parse_port_range(min: Option<u32>, max: Option<u32>, field: &str) -> Result<Option<(u16, u16)>> {
    match (min, max) {
        (None, None) => Ok(None),

        (Some(lo), Some(hi)) => {
            let lo = parse_required_port(lo, &format!("{field}.src_port_min"))?;
            let hi = parse_required_port(hi, &format!("{field}.src_port_max"))?;

            if lo > hi {
                bail!("{field} src_port_min > src_port_max");
            }

            Ok(Some((lo, hi)))
        },

        _ => bail!("{field} src_port_min and src_port_max must both be set or both empty"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pat_rule_maps_to_runtime_port_forward() {
        let cfg = NatConfigRule::Pat {
            id: "pat-1".into(),
            priority: 10,
            common: CommonMatchers { protocol: NatConfigProtocol::Tcp, ..Default::default() },
            dst_ip: "192.168.10.10".into(),
            dst_port: 443,
            translated_ip: "192.168.20.10".into(),
            translated_port: 8443,
        };

        let runtime = cfg.to_runtime_rule().unwrap();

        match runtime.action() {
            NatAction::Pat { dst_ip, dst_port, translated_ip, translated_port } => {
                assert_eq!(*dst_ip, "192.168.10.10".parse::<IpAddr>().unwrap());
                assert_eq!(*dst_port, 443);
                assert_eq!(*translated_ip, "192.168.20.10".parse::<IpAddr>().unwrap());
                assert_eq!(*translated_port, 8443);
            }
            
            _ => panic!("expected Pat"),
        }
        assert_eq!(runtime.protocol(), NatProtocol::Tcp);
    }

    #[test]
    fn masquerade_requires_out_interface() {
        let cfg = NatConfigRule::Masquerade {
            id: "m1".into(),
            priority: 5,
            common: CommonMatchers::default(),
            src_cidr: None,
            src_port_min: None,
            src_port_max: None,
        };
        
        assert!(cfg.to_runtime_rule().is_err());
    }

    #[test]
    fn snat_serde_roundtrip() {
        let cfg = NatConfigRule::Snat {
            id: "s1".into(),
            priority: 20,
            common: CommonMatchers::default(),
            src_cidr: "10.0.0.0/24".into(),
            translated_ip: "203.0.113.5".into(),
            src_port_min: None,
            src_port_max: None,
        };
        
        let json = serde_json::to_string(&cfg).unwrap();
        
        assert!(json.contains("\"action\":\"snat\""));
        
        let back: NatConfigRule = serde_json::from_str(&json).unwrap();
        
        assert_eq!(cfg, back);
    }

    #[test]
    fn dnat_with_translated_port_maps_to_runtime() {
        let cfg = NatConfigRule::Dnat {
            id: "d1".into(),
            priority: 5,
            common: CommonMatchers { protocol: NatConfigProtocol::Tcp, ..Default::default() },
            dst_cidr: "203.0.113.10/32".into(),
            translated_ip: "10.0.0.10".into(),
            translated_port: Some(80),
        };

        let runtime = cfg.to_runtime_rule().unwrap();

        match runtime.action() {
            NatAction::Dnat { dst_cidr, translated_ip, translated_port } => {
                assert_eq!(dst_cidr.to_string(), "203.0.113.10/32");
                assert_eq!(*translated_ip, "10.0.0.10".parse::<IpAddr>().unwrap());
                assert_eq!(*translated_port, Some(80));
            }
            _ => panic!("expected Dnat"),
        }
    }

    #[test]
    fn dnat_without_translated_port_maps_to_runtime() {
        let cfg = NatConfigRule::Dnat {
            id: "d2".into(),
            priority: 5,
            common: CommonMatchers::default(),
            dst_cidr: "10.0.0.0/24".into(),
            translated_ip: "192.168.1.1".into(),
            translated_port: None,
        };

        let runtime = cfg.to_runtime_rule().unwrap();

        match runtime.action() {
            NatAction::Dnat { translated_port, .. } => {
                assert_eq!(*translated_port, None);
            }
            _ => panic!("expected Dnat"),
        }
    }

    #[test]
    fn dnat_serde_roundtrip_with_port() {
        let cfg = NatConfigRule::Dnat {
            id: "d3".into(),
            priority: 10,
            common: CommonMatchers::default(),
            dst_cidr: "203.0.113.0/24".into(),
            translated_ip: "10.0.0.1".into(),
            translated_port: Some(8080),
        };

        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"action\":\"dnat\""));
        assert!(json.contains("\"translated_port\":8080"));

        let back: NatConfigRule = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn dnat_serde_roundtrip_without_port() {
        let cfg = NatConfigRule::Dnat {
            id: "d4".into(),
            priority: 10,
            common: CommonMatchers::default(),
            dst_cidr: "10.0.0.0/8".into(),
            translated_ip: "192.168.1.1".into(),
            translated_port: None,
        };

        let json = serde_json::to_string(&cfg).unwrap();
        let back: NatConfigRule = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn dnat_proto_roundtrip_with_port() {
        let cfg = NatConfigRule::Dnat {
            id: "d5".into(),
            priority: 7,
            common: CommonMatchers { protocol: NatConfigProtocol::Tcp, ..Default::default() },
            dst_cidr: "1.2.3.4/32".into(),
            translated_ip: "10.0.0.5".into(),
            translated_port: Some(443),
        };

        let runtime = cfg.to_runtime_rule().unwrap();
        let proto_msg = runtime.into_proto();
        let back = NatRule::try_from_proto(proto_msg).unwrap();

        assert_eq!(runtime, back);
    }

    #[test]
    fn empty_optional_matchers_are_absent_in_runtime_config() {
        let cfg = NatConfigRule::Dnat {
            id: "d6".into(),
            priority: 7,
            common: CommonMatchers {
                in_interface: Some("".into()),
                out_interface: Some("  ".into()),
                in_zone: Some("".into()),
                out_zone: Some("  ".into()),
                ..Default::default()
            },
            dst_cidr: "203.0.113.10/32".into(),
            translated_ip: "10.0.0.5".into(),
            translated_port: Some(443),
        };

        let runtime = cfg.to_runtime_rule().unwrap();

        assert_eq!(runtime.in_interface(), None);
        assert_eq!(runtime.out_interface(), None);
        assert_eq!(runtime.in_zone(), None);
        assert_eq!(runtime.out_zone(), None);
    }

    #[test]
    fn proto_optional_matchers_are_trimmed_or_absent() {
        let proto = config::NatRule {
            id: "d7".into(),
            priority: 7,
            in_interface: Some(" eth1 ".into()),
            out_interface: Some("".into()),
            in_zone: Some("  ".into()),
            out_zone: Some("zone-b".into()),
            protocol: common::NatProtocol::Tcp as i32,
            match_src_port_min: None,
            match_src_port_max: None,
            match_dst_port_min: None,
            match_dst_port_max: None,
            action: Some(config::nat_rule::Action::Dnat(config::DnatRule {
                dst_cidr: "203.0.113.10/32".into(),
                translated_ip: "10.0.0.5".into(),
                translated_port: Some(443),
            })),
        };

        let runtime = NatRule::try_from_proto(proto).unwrap();

        assert_eq!(runtime.in_interface(), Some("eth1"));
        assert_eq!(runtime.out_interface(), None);
        assert_eq!(runtime.in_zone(), None);
        assert_eq!(runtime.out_zone(), Some("zone-b"));
    }
}
