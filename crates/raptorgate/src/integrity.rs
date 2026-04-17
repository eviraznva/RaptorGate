use std::any::TypeId;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use std::fmt;
use thiserror::Error;

use crate::policy::{Policy, PolicyId};
use crate::zones::{Zone, ZoneId, ZoneInterface, ZoneInterfaceId, ZonePair, ZonePairId};

pub struct ForeignKey {
    pub field: &'static str,
    pub target_type_id: TypeId,
    pub target_type_name: &'static str,
    pub referenced_id: Uuid,
}

pub trait ForeignKeys {
    fn foreign_keys(&self) -> Vec<ForeignKey>;
}

pub fn fk<Id: 'static + Clone + Into<Uuid>>(field: &'static str, id: &Id) -> ForeignKey {
    ForeignKey {
        field,
        target_type_id: TypeId::of::<Id>(),
        target_type_name: std::any::type_name::<Id>(),
        referenced_id: id.clone().into(),
    }
}

macro_rules! foreign_keys {
    ($entity:ty { $($field:ident : $target_id:ty),* $(,)? }) => {
        impl $crate::integrity::ForeignKeys for $entity {
            fn foreign_keys(&self) -> Vec<$crate::integrity::ForeignKey> {
                vec![
                    $($crate::integrity::fk::<$target_id>(stringify!($field), &self.$field),)*
                ]
            }
        }
    };
}
pub(crate) use foreign_keys;


fn short_type_name<T: ?Sized>() -> &'static str {
    let full = std::any::type_name::<T>();
    let last = full.rsplit("::").next().unwrap_or(full);
    last.split('<').next().unwrap_or(last)
}

#[derive(Debug, Error)]
#[error("{source_entity} [{source_id}] field \"{field}\" references {target_type} [{missing_id}] which does not exist")]
pub struct IntegrityError {
    pub source_entity: &'static str,
    pub source_id: Uuid,
    pub field: &'static str,
    pub target_type: &'static str,
    pub missing_id: Uuid,
}

#[derive(Debug, Error)]
pub enum CheckError {
    #[error("{0}")]
    BrokenReference(#[from] IntegrityError),
    #[error("Missing resolver for target type: {target_type}")]
    MissingResolver {
        target_type: &'static str,
        target_type_id: TypeId,
    },
}

pub fn validate_bundle(
    policies: &HashMap<PolicyId, Policy>,
    zone_pairs: &HashMap<ZonePairId, ZonePair>,
    zones: &HashMap<ZoneId, Zone>,
    zone_interfaces: &HashMap<ZoneInterfaceId, ZoneInterface>,
) -> Vec<CheckError> {
    let mut known: HashMap<TypeId, HashSet<Uuid>> = HashMap::new();

    register_ids::<PolicyId, _>(&mut known, policies);
    register_ids::<ZonePairId, _>(&mut known, zone_pairs);
    register_ids::<ZoneId, _>(&mut known, zones);
    register_ids::<ZoneInterfaceId, _>(&mut known, zone_interfaces);

    let mut errors = Vec::new();

    check_collection(short_type_name::<Policy>(), policies, &known, &mut errors);
    check_collection(short_type_name::<ZonePair>(), zone_pairs, &known, &mut errors);
    check_collection(short_type_name::<ZoneInterface>(), zone_interfaces, &known, &mut errors);

    errors
}

fn register_ids<Id: 'static + Clone + Into<Uuid>, V>(
    known: &mut HashMap<TypeId, HashSet<Uuid>>,
    data: &HashMap<Id, V>,
) {
    let ids = data.keys().map(|k| k.clone().into()).collect();
    known.insert(TypeId::of::<Id>(), ids);
}

fn check_collection<Id, V>(
    entity_name: &'static str,
    data: &HashMap<Id, V>,
    known: &HashMap<TypeId, HashSet<Uuid>>,
    errors: &mut Vec<CheckError>,
) where
    Id: Clone + Into<Uuid>,
    V: ForeignKeys,
{
    for (id, entity) in data {
        for fk_ref in entity.foreign_keys() {
            match known.get(&fk_ref.target_type_id) {
                None => errors.push(CheckError::MissingResolver {
                    target_type: fk_ref.target_type_name,
                    target_type_id: fk_ref.target_type_id,
                }),
                Some(ids) => {
                    if !ids.contains(&fk_ref.referenced_id) {
                        errors.push(CheckError::BrokenReference(IntegrityError {
                            source_entity: entity_name,
                            source_id: id.clone().into(),
                            field: fk_ref.field,
                            target_type: fk_ref.target_type_name,
                            missing_id: fk_ref.referenced_id,
                        }));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::config;
    use crate::rule_tree::{RuleTree, MatchBuilder, MatchKind, Pattern, ArmEnd, Verdict};

    fn create_test_policy(id: Uuid, zone_pair_id: Uuid) -> (PolicyId, Policy) {
        let policy_id = PolicyId::from(id);
        let head = MatchBuilder::with_arm(
            MatchKind::SrcIp,
            Pattern::Wildcard,
            ArmEnd::Verdict(Verdict::Allow),
        )
        .build()
        .unwrap();

        let policy = Policy {
            name: "test policy".to_string(),
            zone_pair_id: ZonePairId::from(zone_pair_id),
            priority: 1,
            rule_tree: RuleTree::new(head),
        };
        (policy_id, policy)
    }

    fn create_test_zone(id: Uuid) -> (ZoneId, Zone) {
        let proto = config::Zone {
            id: id.to_string(),
            name: "test zone".to_string(),
            interface_ids: vec![],
        };
        Zone::try_from_proto(proto).unwrap()
    }

    fn create_test_zone_pair(id: Uuid, src_id: Uuid, dst_id: Uuid) -> (ZonePairId, ZonePair) {
        let proto = config::ZonePair {
            id: id.to_string(),
            src_zone_id: src_id.to_string(),
            dst_zone_id: dst_id.to_string(),
            default_policy: 0,
        };
        ZonePair::try_from_proto(proto).unwrap()
    }

    fn create_test_zone_interface(id: Uuid, zone_id: Uuid) -> (ZoneInterfaceId, ZoneInterface) {
        let proto = config::ZoneInterface {
            id: id.to_string(),
            zone_id: zone_id.to_string(),
            interface_name: "eth0".to_string(),
            vlan_id: None,
        };
        ZoneInterface::try_from_proto(proto).unwrap()
    }

    #[test]
    fn valid_bundle_passes() {
        let z_id = Uuid::now_v7();
        let zp_id = Uuid::now_v7();
        let p_id = Uuid::now_v7();
        let zi_id = Uuid::now_v7();

        let mut zones = HashMap::new();
        let (zid, z) = create_test_zone(z_id);
        zones.insert(zid, z);

        let mut zone_pairs = HashMap::new();
        let (zpid, zp) = create_test_zone_pair(zp_id, z_id, z_id);
        zone_pairs.insert(zpid, zp);

        let mut policies = HashMap::new();
        let (pid, p) = create_test_policy(p_id, zp_id);
        policies.insert(pid, p);

        let mut zone_interfaces = HashMap::new();
        let (ziid, zi) = create_test_zone_interface(zi_id, z_id);
        zone_interfaces.insert(ziid, zi);

        let errors = validate_bundle(&policies, &zone_pairs, &zones, &zone_interfaces);
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
    }

    #[test]
    fn missing_zone_pair_ref_detected() {
        let zp_id = Uuid::now_v7();
        let p_id = Uuid::now_v7();

        let mut policies = HashMap::new();
        let (pid, p) = create_test_policy(p_id, zp_id);
        policies.insert(pid, p);

        let errors = validate_bundle(&policies, &HashMap::new(), &HashMap::new(), &HashMap::new());
        assert_eq!(errors.len(), 1);
        if let CheckError::BrokenReference(err) = &errors[0] {
            assert_eq!(err.source_entity, "Policy");
            assert_eq!(err.field, "zone_pair_id");
            assert_eq!(err.missing_id, zp_id);
        } else {
            panic!("Expected BrokenReference error");
        }
    }

    #[test]
    fn missing_zone_ref_detected() {
        let z_id = Uuid::now_v7();
        let zp_id = Uuid::now_v7();

        let mut zone_pairs = HashMap::new();
        let (zpid, zp) = create_test_zone_pair(zp_id, z_id, z_id);
        zone_pairs.insert(zpid, zp);

        let errors = validate_bundle(&HashMap::new(), &zone_pairs, &HashMap::new(), &HashMap::new());
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn multiple_errors_reported() {
        let zp_id = Uuid::now_v7();
        let p_id = Uuid::now_v7();
        let zi_id = Uuid::now_v7();
        let z_id = Uuid::now_v7();

        let mut policies = HashMap::new();
        let (pid, p) = create_test_policy(p_id, zp_id);
        policies.insert(pid, p);

        let mut zone_interfaces = HashMap::new();
        let (ziid, zi) = create_test_zone_interface(zi_id, z_id);
        zone_interfaces.insert(ziid, zi);

        let errors = validate_bundle(&policies, &HashMap::new(), &HashMap::new(), &zone_interfaces);
        assert_eq!(errors.len(), 2);
    }
}
