pub mod netlink;
pub mod provider;

use derive_more::{Display, From, Into};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::proto::{self, common, config};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneInterface {
    pub zone_id: ZoneId,
    pub interface_name: String,
    pub vlan_id: Option<u32>,
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
            },
        ))
    }

    pub fn into_proto(&self, id: ZoneInterfaceId) -> config::ZoneInterface {
        config::ZoneInterface {
            id: Uuid::from(id).into(),
            zone_id: self.zone_id.0.to_string(),
            interface_name: self.interface_name.clone(),
            vlan_id: self.vlan_id,
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, From, Into, Deserialize, Serialize, Display)]
pub struct ZoneInterfaceId(Uuid);

use crate::integrity::foreign_keys;
foreign_keys!(ZonePair { src_zone_id: ZoneId, dst_zone_id: ZoneId });
foreign_keys!(ZoneInterface { zone_id: ZoneId });
