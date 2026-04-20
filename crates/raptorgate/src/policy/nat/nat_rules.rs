use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio::fs;

use crate::policy::nat::nat_rule::NatRule;
use crate::proto::{common, config};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NatRules {
    rules: Vec<NatRule>,
}

impl NatRules {
    pub fn new(mut rules: Vec<NatRule>) -> Self {
        rules.sort_by_key(NatRule::priority);

        Self { rules }
    }

    pub fn rules(&self) -> &[NatRule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn try_from_proto(value: config::NatRuleSet) -> Result<Self, anyhow::Error> {
        value
            .items
            .into_iter()
            .map(NatRule::try_from_proto)
            .collect::<Result<Vec<_>, _>>()
            .map(Self::new)
    }

    pub fn into_proto(&self) -> config::NatRuleSet {
        config::NatRuleSet {
            items: self.rules.iter().map(NatRule::into_proto).collect(),
        }
    }

    pub async fn from_disk(data_dir: impl AsRef<Path>) -> Result<Self> {
        let path = data_dir.as_ref().join("nat_rules.json");
        let raw = fs::read_to_string(&path)
            .await
            .with_context(|| format!("failed to load NAT rules from {}", path.display()))?;

        Self::from_config_json(&raw)
    }

    fn from_config_json(raw: &str) -> Result<Self> {
        let file = serde_json::from_str::<NatRulesFile>(raw)
            .context("failed to parse NAT rules config")?;

        file.items
            .into_iter()
            .filter(|item| item.is_active)
            .map(NatRule::try_from)
            .collect::<Result<Vec<_>>>()
            .map(Self::new)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NatRulesFile {
    items: Vec<NatRuleRecord>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NatRuleRecord {
    id: String,
    #[serde(rename = "type")]
    rule_type: String,
    is_active: bool,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<u32>,
    dst_port: Option<u32>,
    translated_ip: Option<String>,
    translated_port: Option<u32>,
    priority: u32,
}

impl TryFrom<NatRuleRecord> for NatRule {
    type Error = anyhow::Error;

    fn try_from(value: NatRuleRecord) -> Result<Self> {
        NatRule::try_from_proto(config::NatRule {
            id: value.id,
            r#type: nat_rule_type(&value.rule_type)? as i32,
            src_ip: value.src_ip.unwrap_or_default(),
            dst_ip: value.dst_ip.unwrap_or_default(),
            src_port: value.src_port,
            dst_port: value.dst_port,
            translated_ip: value.translated_ip.unwrap_or_default(),
            translated_port: value.translated_port,
            priority: value.priority,
        })
    }
}

fn nat_rule_type(value: &str) -> Result<common::NatRuleType> {
    match value {
        "SNAT" => Ok(common::NatRuleType::Snat),
        "DNAT" => Ok(common::NatRuleType::Dnat),
        "PAT" => Ok(common::NatRuleType::Pat),
        other => bail!("unsupported NAT rule type: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_active_backend_nat_rules() {
        let raw = r#"{
            "items": [
                {
                    "id": "snat-web",
                    "type": "SNAT",
                    "isActive": true,
                    "srcIp": "192.168.1.10",
                    "dstIp": null,
                    "srcPort": null,
                    "dstPort": null,
                    "translatedIp": "203.0.113.10",
                    "translatedPort": null,
                    "priority": 10,
                    "createdAt": "2026-04-20T00:00:00.000Z",
                    "updatedAt": "2026-04-20T00:00:00.000Z",
                    "createdBy": "00000000-0000-4000-8000-000000000001"
                },
                {
                    "id": "disabled",
                    "type": "DNAT",
                    "isActive": false,
                    "dstIp": "203.0.113.20",
                    "translatedIp": "192.168.1.20",
                    "priority": 20,
                    "createdAt": "2026-04-20T00:00:00.000Z",
                    "updatedAt": "2026-04-20T00:00:00.000Z",
                    "createdBy": "00000000-0000-4000-8000-000000000001"
                }
            ]
        }"#;

        let rules = NatRules::from_config_json(raw).unwrap();

        assert_eq!(rules.rules().len(), 1);
        assert_eq!(rules.rules()[0].id(), "snat-web");
    }
}
