use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use ipnet::IpNet;

use crate::proto::{common, config};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatProtocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatAction {
    Pat,
    Dnat,
    Snat,
    Masquerade,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatRule {
    id: String,
    priority: u32,
    in_interface: Option<String>,
    out_interface: Option<String>,
    in_zone: Option<String>,
    out_zone: Option<String>,
    src_cidr: Option<IpNet>,
    dst_cidr: Option<IpNet>,
    protocol: Option<NatProtocol>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    translated_ip: Option<IpAddr>,
    translated_port: Option<u16>,
    action: NatAction,
}

impl NatRule {
    pub fn new(
        id: String,
        priority: u32,
        in_interface: Option<String>,
        out_interface: Option<String>,
        in_zone: Option<String>,
        out_zone: Option<String>,
        src_cidr: Option<IpNet>,
        dst_cidr: Option<IpNet>,
        protocol: Option<NatProtocol>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        translated_ip: Option<IpAddr>,
        translated_port: Option<u16>,
        action: NatAction,
    ) -> Self {
        Self {
            id,
            priority,
            in_interface,
            out_interface,
            in_zone,
            out_zone,
            src_cidr,
            dst_cidr,
            protocol,
            src_port,
            dst_port,
            translated_ip,
            translated_port,
            action,
        }
    }

    pub fn try_from_proto(value: config::NatRule) -> Result<Self> {
        let action = match common::NatRuleType::try_from(value.r#type)
            .context("invalid nat rule type")?
        {
            common::NatRuleType::Snat => NatAction::Snat,
            common::NatRuleType::Dnat => NatAction::Dnat,
            common::NatRuleType::Pat => NatAction::Pat,
            common::NatRuleType::Unspecified => bail!("nat rule type is unspecified"),
        };

        let translated_ip = parse_optional_ip(&value.translated_ip, "translated_ip")?;
        if translated_ip.is_none() {
            bail!("translated_ip is required");
        }

        Ok(Self::new(
            value.id,
            value.priority,
            None,
            None,
            None,
            None,
            parse_optional_net(&value.src_ip, "src_ip")?,
            parse_optional_net(&value.dst_ip, "dst_ip")?,
            None,
            parse_optional_port(value.src_port, "src_port")?,
            parse_optional_port(value.dst_port, "dst_port")?,
            translated_ip,
            parse_optional_port(value.translated_port, "translated_port")?,
            action,
        ))
    }

    pub fn into_proto(&self) -> config::NatRule {
        config::NatRule {
            id: self.id.clone(),
            r#type: match self.action {
                NatAction::Snat => common::NatRuleType::Snat,
                NatAction::Dnat => common::NatRuleType::Dnat,
                NatAction::Pat => common::NatRuleType::Pat,
                NatAction::Masquerade => common::NatRuleType::Unspecified,
            } as i32,
            src_ip: net_to_string(self.src_cidr),
            dst_ip: net_to_string(self.dst_cidr),
            src_port: self.src_port.map(u32::from),
            dst_port: self.dst_port.map(u32::from),
            translated_ip: self
                .translated_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            translated_port: self.translated_port.map(u32::from),
            priority: self.priority,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn priority(&self) -> u32 {
        self.priority
    }
    pub fn in_interface(&self) -> Option<&str> {
        self.in_interface.as_ref().map(|s| s.as_str())
    }
    pub fn out_interface(&self) -> Option<&str> {
        self.out_interface.as_ref().map(|s| s.as_str())
    }
    pub fn in_zone(&self) -> Option<&str> {
        self.in_zone.as_ref().map(|s| s.as_str())
    }
    pub fn out_zone(&self) -> Option<&str> {
        self.out_zone.as_ref().map(|s| s.as_str())
    }
    pub fn src_cidr(&self) -> Option<IpNet> {
        self.src_cidr
    }
    pub fn dst_cidr(&self) -> Option<IpNet> {
        self.dst_cidr
    }
    pub fn protocol(&self) -> Option<NatProtocol> {
        self.protocol
    }
    pub fn src_port(&self) -> Option<u16> {
        self.src_port
    }
    pub fn dst_port(&self) -> Option<u16> {
        self.dst_port
    }
    pub fn translated_ip(&self) -> Option<IpAddr> {
        self.translated_ip
    }
    pub fn translated_port(&self) -> Option<u16> {
        self.translated_port
    }
    pub fn action(&self) -> NatAction {
        self.action.clone()
    }
}

fn parse_optional_net(value: &str, field: &str) -> Result<Option<IpNet>> {
    if value.is_empty() {
        return Ok(None);
    }

    if value.contains('/') {
        return value
            .parse::<IpNet>()
            .with_context(|| format!("invalid {field}"))
            .map(Some);
    }

    let ip = value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid {field}"))?;
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    IpNet::new(ip, prefix)
        .with_context(|| format!("invalid {field}"))
        .map(Some)
}

fn parse_optional_ip(value: &str, field: &str) -> Result<Option<IpAddr>> {
    if value.is_empty() {
        return Ok(None);
    }

    value
        .parse::<IpAddr>()
        .with_context(|| format!("invalid {field}"))
        .map(Some)
}

fn parse_optional_port(value: Option<u32>, field: &str) -> Result<Option<u16>> {
    let Some(value) = value else {
        return Ok(None);
    };

    if value == 0 {
        bail!("{field} must be between 1 and 65535");
    }

    u16::try_from(value)
        .with_context(|| format!("{field} must be between 1 and 65535"))
        .map(Some)
}

fn net_to_string(value: Option<IpNet>) -> String {
    match value {
        Some(IpNet::V4(net)) if net.prefix_len() == 32 => net.addr().to_string(),
        Some(IpNet::V6(net)) if net.prefix_len() == 128 => net.addr().to_string(),
        Some(net) => net.to_string(),
        None => String::new(),
    }
}
