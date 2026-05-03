pub mod provider;
pub mod resolver;

use derive_more::{Display, From, Into};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::proto::{common, config};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    name: String,
}

impl Zone {
    pub fn try_from_proto(value: config::Zone) -> Result<(ZoneId, Self), anyhow::Error> {
        let id = ZoneId(Uuid::parse_str(&value.id)?);
        Ok((
            id,
            Self {
                name: value.name,
            },
        ))
    }

    pub fn into_proto(&self, id: ZoneId) -> config::Zone {
        config::Zone {
            id: Uuid::from(id).into(),
            name: self.name.clone(),
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VlanId(u32);

#[derive(Debug, thiserror::Error)]
#[error("VLAN ID {0} out of range (1-4094)")]
pub struct VlanIdRangeError(u32);

impl TryFrom<u32> for VlanId {
    type Error = VlanIdRangeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if (1..=4094).contains(&value) {
            Ok(Self(value))
        } else {
            Err(VlanIdRangeError(value))
        }
    }
}

impl std::fmt::Display for VlanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<VlanId> for u32 {
    fn from(id: VlanId) -> u32 {
        id.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalInterface {
    pub interface_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanSubinterface {
    pub parent_interface_id: ZoneInterfaceId,
    pub vlan_id: VlanId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZoneInterfaceKind {
    Physical(PhysicalInterface),
    Vlan(VlanSubinterface),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneInterface {
    pub zone_id: ZoneId,
    pub kind: ZoneInterfaceKind,
    #[serde(default)]
    pub status: InterfaceStatus,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub sniffed: bool,
}

impl ZoneInterface {
    pub fn try_from_proto(value: config::ZoneInterface) -> Result<(ZoneInterfaceId, Self), anyhow::Error> {
        let id = ZoneInterfaceId(Uuid::parse_str(&value.id)?);
        let zone_id = ZoneId(Uuid::parse_str(&value.zone_id)?);
        
        let kind = match value.kind {
            Some(config::zone_interface::Kind::Physical(p)) => {
                ZoneInterfaceKind::Physical(PhysicalInterface {
                    interface_name: p.interface_name,
                })
            }
            Some(config::zone_interface::Kind::Vlan(v)) => {
                let parent_interface_id = ZoneInterfaceId(Uuid::parse_str(&v.parent_interface_id)?);
                let vlan_id = VlanId::try_from(v.vlan_id)?;
                ZoneInterfaceKind::Vlan(VlanSubinterface {
                    parent_interface_id,
                    vlan_id,
                })
            }
            None => anyhow::bail!("ZoneInterface kind is required"),
        };
        
        Ok((
            id,
            Self {
                zone_id,
                kind,
                status: InterfaceStatus::try_from(value.status)?,
                addresses: value.addresses,
                sniffed: value.sniffed,
            },
        ))
    }

    pub fn into_proto(&self, id: ZoneInterfaceId) -> config::ZoneInterface {
        let kind = match &self.kind {
            ZoneInterfaceKind::Physical(p) => {
                Some(config::zone_interface::Kind::Physical(config::PhysicalInterface {
                    interface_name: p.interface_name.clone(),
                }))
            }
            ZoneInterfaceKind::Vlan(v) => {
                Some(config::zone_interface::Kind::Vlan(config::VlanSubinterface {
                    parent_interface_id: v.parent_interface_id.0.to_string(),
                    vlan_id: v.vlan_id.into(),
                }))
            }
        };
        
        config::ZoneInterface {
            id: Uuid::from(id).into(),
            zone_id: self.zone_id.0.to_string(),
            status: self.status.clone().into(),
            addresses: self.addresses.clone(),
            kind,
            sniffed: self.sniffed,
        }
    }

    pub fn interface_name(&self) -> &str {
        match &self.kind {
            ZoneInterfaceKind::Physical(p) => &p.interface_name,
            ZoneInterfaceKind::Vlan(_) => "",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePair {
    pub src_zone_id: ZoneId,
    pub dst_zone_id: ZoneId,
    pub default_policy: DefaultPolicy,
}

#[derive(Debug, Clone)]
pub struct ResolvedZonePair {
    pub id: ZonePairId,
    pub default_policy: DefaultPolicy,
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

use crate::validation::{foreign_keys, fk, ForeignKey, ForeignKeys};
foreign_keys!(ZonePair { src_zone_id: ZoneId, dst_zone_id: ZoneId });

impl ForeignKeys for ZoneInterface {
    fn foreign_keys(&self) -> Vec<ForeignKey> {
        let mut keys = vec![fk::<ZoneId>("zone_id", &self.zone_id)];
        if let ZoneInterfaceKind::Vlan(vlan) = &self.kind {
            keys.push(fk::<ZoneInterfaceId>("parent_interface_id", &vlan.parent_interface_id));
        }
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uuid() -> Uuid {
        Uuid::now_v7()
    }

    #[test]
    fn vlan_id_accepts_valid_range() {
        assert!(VlanId::try_from(1).is_ok());
        assert!(VlanId::try_from(100).is_ok());
        assert!(VlanId::try_from(4094).is_ok());
    }

    #[test]
    fn vlan_id_rejects_zero() {
        let result = VlanId::try_from(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "VLAN ID 0 out of range (1-4094)");
    }

    #[test]
    fn vlan_id_rejects_over_4094() {
        assert!(VlanId::try_from(4095).is_err());
        assert!(VlanId::try_from(9999).is_err());
    }

    #[test]
    fn vlan_id_serde_roundtrip() {
        let vlan_id = VlanId::try_from(100).unwrap();
        let json = serde_json::to_string(&vlan_id).unwrap();
        let deserialized: VlanId = serde_json::from_str(&json).unwrap();
        assert_eq!(vlan_id, deserialized);
    }

    #[test]
    fn zone_interface_physical_serde_roundtrip() {
        let zi = ZoneInterface {
            zone_id: ZoneId(test_uuid()),
            kind: ZoneInterfaceKind::Physical(PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec!["192.168.1.1".to_string()],
            sniffed: true,
        };
        let json = serde_json::to_string(&zi).unwrap();
        let deserialized: ZoneInterface = serde_json::from_str(&json).unwrap();
        assert_eq!(zi.zone_id, deserialized.zone_id);
        assert_eq!(zi.sniffed, deserialized.sniffed);
    }

    #[test]
    fn zone_interface_vlan_serde_roundtrip() {
        let parent_id = ZoneInterfaceId(test_uuid());
        let zi = ZoneInterface {
            zone_id: ZoneId(test_uuid()),
            kind: ZoneInterfaceKind::Vlan(VlanSubinterface {
                parent_interface_id: parent_id,
                vlan_id: VlanId::try_from(100).unwrap(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        let json = serde_json::to_string(&zi).unwrap();
        let deserialized: ZoneInterface = serde_json::from_str(&json).unwrap();
        assert_eq!(zi.zone_id, deserialized.zone_id);
        assert_eq!(zi.sniffed, deserialized.sniffed);
    }

    #[test]
    fn zone_interface_physical_proto_roundtrip() {
        let id = ZoneInterfaceId(test_uuid());
        let zi = ZoneInterface {
            zone_id: ZoneId(test_uuid()),
            kind: ZoneInterfaceKind::Physical(PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec!["10.0.0.1".to_string()],
            sniffed: true,
        };
        let proto = zi.into_proto(id.clone());
        let (roundtrip_id, roundtrip) = ZoneInterface::try_from_proto(proto).unwrap();
        assert_eq!(id, roundtrip_id);
        assert_eq!(zi.zone_id, roundtrip.zone_id);
        assert_eq!(zi.sniffed, roundtrip.sniffed);
    }

    #[test]
    fn zone_interface_vlan_proto_roundtrip() {
        let id = ZoneInterfaceId(test_uuid());
        let parent_id = ZoneInterfaceId(test_uuid());
        let zi = ZoneInterface {
            zone_id: ZoneId(test_uuid()),
            kind: ZoneInterfaceKind::Vlan(VlanSubinterface {
                parent_interface_id: parent_id.clone(),
                vlan_id: VlanId::try_from(200).unwrap(),
            }),
            status: InterfaceStatus::Missing,
            addresses: vec![],
            sniffed: false,
        };
        let proto = zi.into_proto(id.clone());
        let (roundtrip_id, roundtrip) = ZoneInterface::try_from_proto(proto).unwrap();
        assert_eq!(id, roundtrip_id);
        assert_eq!(zi.zone_id, roundtrip.zone_id);
        if let ZoneInterfaceKind::Vlan(v) = &roundtrip.kind {
            assert_eq!(v.parent_interface_id, parent_id);
            assert_eq!(u32::from(v.vlan_id), 200);
        } else {
            panic!("Expected Vlan variant");
        }
    }

    #[test]
    fn zone_interface_vlan_rejects_invalid_vlan_id() {
        let proto = config::ZoneInterface {
            id: test_uuid().to_string(),
            zone_id: test_uuid().to_string(),
            status: config::InterfaceStatus::Active as i32,
            addresses: vec![],
            kind: Some(config::zone_interface::Kind::Vlan(config::VlanSubinterface {
                parent_interface_id: test_uuid().to_string(),
                vlan_id: 0,
            })),
            sniffed: false,
        };
        assert!(ZoneInterface::try_from_proto(proto).is_err());
    }

    #[test]
    fn zone_interface_vlan_rejects_invalid_vlan_id_over_4094() {
        let proto = config::ZoneInterface {
            id: test_uuid().to_string(),
            zone_id: test_uuid().to_string(),
            status: config::InterfaceStatus::Active as i32,
            addresses: vec![],
            kind: Some(config::zone_interface::Kind::Vlan(config::VlanSubinterface {
                parent_interface_id: test_uuid().to_string(),
                vlan_id: 5000,
            })),
            sniffed: false,
        };
        assert!(ZoneInterface::try_from_proto(proto).is_err());
    }

    #[test]
    fn foreign_keys_physical_returns_zone_id_only() {
        let zi = ZoneInterface {
            zone_id: ZoneId(test_uuid()),
            kind: ZoneInterfaceKind::Physical(PhysicalInterface {
                interface_name: "eth0".to_string(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        let fks = zi.foreign_keys();
        assert_eq!(fks.len(), 1);
        assert_eq!(fks[0].field, "zone_id");
    }

    #[test]
    fn foreign_keys_vlan_returns_zone_id_and_parent() {
        let zi = ZoneInterface {
            zone_id: ZoneId(test_uuid()),
            kind: ZoneInterfaceKind::Vlan(VlanSubinterface {
                parent_interface_id: ZoneInterfaceId(test_uuid()),
                vlan_id: VlanId::try_from(100).unwrap(),
            }),
            status: InterfaceStatus::Active,
            addresses: vec![],
            sniffed: false,
        };
        let fks = zi.foreign_keys();
        assert_eq!(fks.len(), 2);
        assert_eq!(fks[0].field, "zone_id");
        assert_eq!(fks[1].field, "parent_interface_id");
    }

    #[test]
    fn sniffed_defaults_to_false() {
        let json = r#"{
            "zone_id": "00000000-0000-0000-0000-000000000000",
            "kind": {
                "Physical": {
                    "interface_name": "eth0"
                }
            }
        }"#;
        let zi: ZoneInterface = serde_json::from_str(json).unwrap();
        assert_eq!(zi.sniffed, false);
    }
}
