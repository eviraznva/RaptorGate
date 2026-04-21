use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::policy::nat::nat_rule::{NatAction, NatProtocol, NatRule};
use crate::policy::nat::nat_rules::NatRules;
use crate::proto::common::NatRuleType;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatConfig {
    #[serde(default)]
    pub rules: Vec<NatConfigRule>,
}

impl NatConfig {
    pub fn from_proto_rules(rules: &[crate::proto::config::NatRule]) -> Result<Self> {
        let mut items = Vec::with_capacity(rules.len());

        for rule in rules {
            items.push(NatConfigRule::from_proto(rule)?);
        }

        Ok(Self { rules: items })
    }

    pub fn to_runtime_rules(&self) -> Result<Option<std::sync::Arc<NatRules>>> {
        if self.rules.is_empty() {
            return Ok(None);
        }

        let mut runtime_rules = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            runtime_rules.push(rule.to_runtime_rule()?);
        }

        Ok(Some(std::sync::Arc::new(NatRules::new(runtime_rules))))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatConfigRule {
    pub id: String,
    pub rule_type: NatConfigRuleType,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub translated_ip: Option<String>,
    pub translated_port: Option<u16>,
    pub priority: u32,
}

impl NatConfigRule {
    pub fn from_proto(rule: &crate::proto::config::NatRule) -> Result<Self> {
        let rule_type = match NatRuleType::try_from(rule.r#type).context("invalid nat rule type")? {
            NatRuleType::Snat => NatConfigRuleType::Snat,
            NatRuleType::Dnat => NatConfigRuleType::Dnat,
            NatRuleType::Pat => NatConfigRuleType::Pat,
            NatRuleType::Unspecified => bail!("nat rule '{}' has unspecified type", rule.id),
        };

        Ok(Self {
            id: rule.id.clone(),
            rule_type,
            src_ip: normalize_proto_text(&rule.src_ip),
            dst_ip: normalize_proto_text(&rule.dst_ip),
            src_port: rule.src_port.and_then(|port| u16::try_from(port).ok()),
            dst_port: rule.dst_port.and_then(|port| u16::try_from(port).ok()),
            translated_ip: normalize_proto_text(&rule.translated_ip),
            translated_port: rule
                .translated_port
                .and_then(|port| u16::try_from(port).ok()),
            priority: rule.priority,
        })
    }

    pub fn to_runtime_rule(&self) -> Result<NatRule> {
        let src_cidr = parse_optional_ipnet(self.src_ip.as_deref(), "src_ip")?;
        let dst_cidr = parse_optional_ipnet(self.dst_ip.as_deref(), "dst_ip")?;
        let translated_ip = parse_optional_ipaddr(self.translated_ip.as_deref(), "translated_ip")?;

        let (action, protocol) = match self.rule_type {
            NatConfigRuleType::Snat => (NatAction::Snat, None),
            NatConfigRuleType::Dnat => (NatAction::Dnat, None),
            NatConfigRuleType::Pat => (NatAction::Pat, Some(NatProtocol::Tcp)),
        };

        match self.rule_type {
            NatConfigRuleType::Snat if src_cidr.is_none() || translated_ip.is_none() => {
                bail!("SNAT rule '{}' requires src_ip and translated_ip", self.id);
            }
            NatConfigRuleType::Dnat if dst_cidr.is_none() || translated_ip.is_none() => {
                bail!("DNAT rule '{}' requires dst_ip and translated_ip", self.id);
            }
            NatConfigRuleType::Pat
                if dst_cidr.is_none()
                    || self.dst_port.is_none()
                    || translated_ip.is_none()
                    || self.translated_port.is_none() =>
            {
                bail!(
                    "PAT rule '{}' requires dst_ip, dst_port, translated_ip and translated_port",
                    self.id
                );
            }
            _ => {}
        }

        Ok(NatRule::new(
            self.id.clone(),
            self.priority,
            None,
            None,
            None,
            None,
            src_cidr,
            dst_cidr,
            protocol,
            self.src_port,
            self.dst_port,
            translated_ip,
            self.translated_port,
            action,
        ))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NatConfigRuleType {
    Snat,
    Dnat,
    Pat,
}

fn normalize_proto_text(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn parse_optional_ipaddr(value: Option<&str>, field: &str) -> Result<Option<IpAddr>> {
    value
        .map(|raw| raw.parse::<IpAddr>().with_context(|| format!("invalid {field}: {raw}")))
        .transpose()
}

fn parse_optional_ipnet(value: Option<&str>, field: &str) -> Result<Option<IpNet>> {
    value.map(|raw| parse_ipnet(raw, field)).transpose()
}

fn parse_ipnet(value: &str, field: &str) -> Result<IpNet> {
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(net);
    }

    let addr = value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid {field}: {value}"))?;

    Ok(match addr {
        IpAddr::V4(addr) => IpNet::from(IpAddr::V4(addr)),
        IpAddr::V6(addr) => IpNet::from(IpAddr::V6(addr)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pat_rule_maps_to_runtime_port_forward() {
        let config = NatConfigRule {
            id: "pat-1".into(),
            rule_type: NatConfigRuleType::Pat,
            src_ip: None,
            dst_ip: Some("192.168.10.10".into()),
            src_port: None,
            dst_port: Some(443),
            translated_ip: Some("192.168.20.10".into()),
            translated_port: Some(8443),
            priority: 10,
        };

        let runtime = config.to_runtime_rule().unwrap();

        assert_eq!(runtime.action(), NatAction::Pat);
        assert_eq!(runtime.dst_port(), Some(443));
        assert_eq!(runtime.translated_ip(), Some("192.168.20.10".parse().unwrap()));
        assert_eq!(runtime.translated_port(), Some(8443));
        assert_eq!(runtime.protocol(), Some(NatProtocol::Tcp));
    }

    #[test]
    fn host_ip_without_prefix_becomes_single_host_net() {
        let parsed = parse_ipnet("192.168.20.10", "dst_ip").unwrap();
        assert_eq!(parsed, "192.168.20.10/32".parse().unwrap());
    }
}
