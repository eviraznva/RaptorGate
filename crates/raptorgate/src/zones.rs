pub mod provider;

use derive_more::{Display, From, Into};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::proto::{common, config};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    name: String,
    interface_ids: Vec<String>,
}

impl Zone {
    pub fn try_from_proto(value: config::Zone) -> Result<(ZoneId, Self), anyhow::Error> {
        let id = ZoneId(Uuid::parse_str(&value.id)?);
        Ok((
            id,
            Self {
                name: value.name,
                interface_ids: value.interface_ids,
            },
        ))
    }

    pub fn into_proto(&self, id: ZoneId) -> config::Zone {
        config::Zone {
            id: Uuid::from(id).into(),
            name: self.name.clone(),
            interface_ids: self.interface_ids.clone(),
        }
    }

    pub fn interface_ids(&self) -> &[String] {
        &self.interface_ids
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InterfaceStatus {
    Unspecified,
    Active,
    Inactive,
    Missing,
    Unknown,
}

impl Default for InterfaceStatus {
    fn default() -> Self {
        Self::Unspecified
    }
}

impl TryFrom<i32> for InterfaceStatus {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let status = config::InterfaceStatus::try_from(value)?;
        Ok(match status {
            config::InterfaceStatus::Unspecified => Self::Unspecified,
            config::InterfaceStatus::Active => Self::Active,
            config::InterfaceStatus::Inactive => Self::Inactive,
            config::InterfaceStatus::Missing => Self::Missing,
            config::InterfaceStatus::Unknown => Self::Unknown,
        })
    }
}

impl From<InterfaceStatus> for i32 {
    fn from(value: InterfaceStatus) -> Self {
        match value {
            InterfaceStatus::Unspecified => config::InterfaceStatus::Unspecified as i32,
            InterfaceStatus::Active => config::InterfaceStatus::Active as i32,
            InterfaceStatus::Inactive => config::InterfaceStatus::Inactive as i32,
            InterfaceStatus::Missing => config::InterfaceStatus::Missing as i32,
            InterfaceStatus::Unknown => config::InterfaceStatus::Unknown as i32,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneInterface {
    pub zone_id: ZoneId,
    pub interface_name: String,
    pub vlan_id: Option<u32>,
    #[serde(default)]
    pub status: InterfaceStatus,
    #[serde(default)]
    pub addresses: Vec<String>,
}

impl ZoneInterface {
    pub fn try_from_proto(value: config::ZoneInterface) -> Result<(ZoneInterfaceId, Self), anyhow::Error> {
        let id = ZoneInterfaceId(Uuid::parse_str(&value.id)?);
        let zone_id = ZoneId(Uuid::parse_str(&value.zone_id)?);
        Ok((
            id,
            Self {
                zone_id,
                interface_name: value.interface_name,
                vlan_id: value.vlan_id,
                status: InterfaceStatus::try_from(value.status)?,
                addresses: value.addresses,
            },
        ))
    }

    pub fn into_proto(&self, id: ZoneInterfaceId) -> config::ZoneInterface {
        config::ZoneInterface {
            id: Uuid::from(id).into(),
            zone_id: self.zone_id.0.to_string(),
            interface_name: self.interface_name.clone(),
            vlan_id: self.vlan_id,
            status: self.status.clone().into(),
            addresses: self.addresses.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePair {
    src_zone_id: ZoneId,
    dst_zone_id: ZoneId,
    default_policy: DefaultPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DefaultPolicy {
    Unspecified,
    Allow,
    Drop,
}

impl From<common::DefaultPolicy> for DefaultPolicy {
    fn from(value: common::DefaultPolicy) -> Self {
        use common::DefaultPolicy as External;
        match value {
            External::Unspecified => DefaultPolicy::Unspecified,
            External::Allow => DefaultPolicy::Allow,
            External::Drop => DefaultPolicy::Drop,
        }
    }
}

impl ZonePair {
    pub fn try_from_proto(value: config::ZonePair) -> Result<(ZonePairId, Self), anyhow::Error> {
        let id = ZonePairId(Uuid::parse_str(&value.id)?);
        let src_zone_id = ZoneId(Uuid::parse_str(&value.src_zone_id)?);
        let dst_zone_id = ZoneId(Uuid::parse_str(&value.dst_zone_id)?);
        Ok((
            id,
            Self {
                src_zone_id,
                dst_zone_id,
                default_policy: DefaultPolicy::from(common::DefaultPolicy::try_from(value.default_policy)?),
            },
        ))
    }

    pub fn into_proto(&self, id: ZonePairId) -> config::ZonePair {
        config::ZonePair {
            id: Uuid::from(id).to_string(),
            src_zone_id: self.src_zone_id.0.to_string(),
            dst_zone_id: self.dst_zone_id.0.to_string(),
            default_policy: self.default_policy.clone() as i32,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, From, Into, Deserialize, Serialize, Display)]
pub struct ZonePairId(Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, From, Into, Deserialize, Serialize, Display)]
pub struct ZoneId(Uuid);

pub const DEFAULT_ZONE_ID: ZoneId = ZoneId(Uuid::nil());

#[derive(Clone, Debug, PartialEq, Eq, Hash, From, Into, Deserialize, Serialize, Display)]
pub struct ZoneInterfaceId(Uuid);

use crate::validation::{fk, foreign_keys, ForeignKey, ForeignKeys};
impl ForeignKeys for Zone {
    fn foreign_keys(&self) -> Vec<ForeignKey> {
        self.interface_ids
            .iter()
            .filter_map(|interface_id| {
                Uuid::parse_str(interface_id)
                    .ok()
                    .map(ZoneInterfaceId::from)
            })
            .map(|interface_id| fk::<ZoneInterfaceId>("interface_ids", &interface_id))
            .collect()
    }
}
foreign_keys!(ZonePair { src_zone_id: ZoneId, dst_zone_id: ZoneId });
foreign_keys!(ZoneInterface { zone_id: ZoneId });
