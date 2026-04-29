use std::any::TypeId;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use thiserror::Error;
use uuid::Uuid;

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
        impl $crate::validation::ForeignKeys for $entity {
            fn foreign_keys(&self) -> Vec<$crate::validation::ForeignKey> {
                vec![
                    $($crate::validation::fk::<$target_id>(stringify!($field), &self.$field),)*
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
    #[error("Missing default zone (id: {missing_id})")]
    MissingDefaultZone { missing_id: Uuid },
    #[error("Duplicate zone interface name '{name}' for ids {first_id} and {second_id}")]
    DuplicateZoneInterfaceName {
        name: String,
        first_id: Uuid,
        second_id: Uuid,
    },
}

pub fn validate_bundle<S: BuildHasher>(
    policies: &HashMap<PolicyId, Policy, S>,
    zone_pairs: &HashMap<ZonePairId, ZonePair, S>,
    zones: &HashMap<ZoneId, Zone, S>,
    zone_interfaces: &HashMap<ZoneInterfaceId, ZoneInterface, S>,
) -> Vec<CheckError> {
    let mut known: HashMap<TypeId, HashSet<Uuid>> = HashMap::new();

    register_ids(&mut known, policies);
    register_ids(&mut known, zone_pairs);
    register_ids(&mut known, zones);
    register_ids(&mut known, zone_interfaces);

    let mut errors = Vec::new();

    check_default_zone_present(zones, &mut errors);
    check_zone_interface_id_format(zones, &mut errors);
    check_duplicate_zone_interface_names(zone_interfaces, &mut errors);
    check_collection(short_type_name::<Policy>(), policies, &known, &mut errors);
    check_collection(short_type_name::<Zone>(), zones, &known, &mut errors);
    check_collection(
        short_type_name::<ZonePair>(),
        zone_pairs,
        &known,
        &mut errors,
    );
    check_collection(
        short_type_name::<ZoneInterface>(),
        zone_interfaces,
        &known,
        &mut errors,
    );

    errors
}

fn check_default_zone_present<S: BuildHasher>(
    zones: &HashMap<ZoneId, Zone, S>,
    errors: &mut Vec<CheckError>,
) {
    let default_id = Uuid::nil();
    if !zones.keys().any(|id| Uuid::from(id.clone()) == default_id) {
        errors.push(CheckError::MissingDefaultZone {
            missing_id: default_id,
        });
    }
}

fn check_duplicate_zone_interface_names<S: BuildHasher>(
    zone_interfaces: &HashMap<ZoneInterfaceId, ZoneInterface, S>,
    errors: &mut Vec<CheckError>,
) {
    let mut seen: HashMap<&str, Uuid> = HashMap::new();
    for (id, zone_interface) in zone_interfaces {
        let name = zone_interface.interface_name.as_str();
        let id_uuid = Uuid::from(id.clone());
        if let Some(existing) = seen.insert(name, id_uuid) {
            errors.push(CheckError::DuplicateZoneInterfaceName {
                name: name.to_string(),
                first_id: existing,
                second_id: id_uuid,
            });
        }
    }
}

fn register_ids<Id, V, S>(known: &mut HashMap<TypeId, HashSet<Uuid>>, data: &HashMap<Id, V, S>)
where
    Id: 'static + Clone + Into<Uuid>,
    S: BuildHasher,
{
    let ids = data.keys().map(|k| k.clone().into()).collect();
    known.insert(TypeId::of::<Id>(), ids);
}

fn check_collection<Id, V, S>(
    entity_name: &'static str,
    data: &HashMap<Id, V, S>,
    known: &HashMap<TypeId, HashSet<Uuid>>,
    errors: &mut Vec<CheckError>,
) where
    Id: Clone + Into<Uuid>,
    V: ForeignKeys,
    S: BuildHasher,
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

fn check_zone_interface_id_format<S: BuildHasher>(
    zones: &HashMap<ZoneId, Zone, S>,
    errors: &mut Vec<CheckError>,
) {
    for (zone_id, zone) in zones {
        for interface_id in zone.interface_ids() {
            if Uuid::parse_str(interface_id).is_err() {
                errors.push(CheckError::BrokenReference(IntegrityError {
                    source_entity: short_type_name::<Zone>(),
                    source_id: zone_id.clone().into(),
                    field: "interface_ids",
                    target_type: std::any::type_name::<ZoneInterfaceId>(),
                    missing_id: Uuid::nil(),
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::config;
    use crate::rule_tree::{ArmEnd, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict};

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

    fn create_test_zone(id: Uuid, interface_ids: Vec<String>) -> (ZoneId, Zone) {
        let proto = config::Zone {
            id: id.to_string(),
            name: "test zone".to_string(),
            interface_ids,
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
            status: config::InterfaceStatus::Unspecified as i32,
            addresses: vec![],
        };
        ZoneInterface::try_from_proto(proto).unwrap()
    }

    #[test]
    fn valid_bundle_passes() {
        let z_id = Uuid::nil();
        let zp_id = Uuid::now_v7();
        let p_id = Uuid::now_v7();
        let zi_id = Uuid::now_v7();

        let mut zones = HashMap::new();
        let (zid, z) = create_test_zone(z_id, vec![zi_id.to_string()]);
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
    fn missing_default_zone_detected() {
        let z_id = Uuid::now_v7();
        let zp_id = Uuid::now_v7();
        let p_id = Uuid::now_v7();
        let zi_id = Uuid::now_v7();

        let mut zones = HashMap::new();
        let (zid, z) = create_test_zone(z_id, vec![zi_id.to_string()]);
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
        assert!(errors
            .iter()
            .any(|err| matches!(err, CheckError::MissingDefaultZone { .. })));
    }

    #[test]
    fn duplicate_zone_interface_name_detected() {
        let z_id = Uuid::nil();
        let zp_id = Uuid::now_v7();
        let p_id = Uuid::now_v7();
        let zi_id = Uuid::now_v7();
        let zi2_id = Uuid::now_v7();

        let mut zones = HashMap::new();
        let (zid, z) = create_test_zone(z_id, vec![zi_id.to_string(), zi2_id.to_string()]);
        zones.insert(zid, z);

        let mut zone_pairs = HashMap::new();
        let (zpid, zp) = create_test_zone_pair(zp_id, z_id, z_id);
        zone_pairs.insert(zpid, zp);

        let mut policies = HashMap::new();
        let (pid, p) = create_test_policy(p_id, zp_id);
        policies.insert(pid, p);

        let mut zone_interfaces = HashMap::new();
        let (ziid, zi) = create_test_zone_interface(zi_id, z_id);
        let (zi2id, mut zi2) = create_test_zone_interface(zi2_id, z_id);
        zi2.interface_name = zi.interface_name.clone();
        zone_interfaces.insert(ziid, zi);
        zone_interfaces.insert(zi2id, zi2);

        let errors = validate_bundle(&policies, &zone_pairs, &zones, &zone_interfaces);
        assert!(errors
            .iter()
            .any(|err| matches!(err, CheckError::DuplicateZoneInterfaceName { .. })));
    }

    #[test]
    fn missing_zone_pair_ref_detected() {
        let zp_id = Uuid::now_v7();
        let p_id = Uuid::now_v7();

        let mut policies = HashMap::new();
        let (pid, p) = create_test_policy(p_id, zp_id);
        policies.insert(pid, p);

        let default_zone = create_test_zone(Uuid::nil(), vec![]);
        let mut zones = HashMap::new();
        zones.insert(default_zone.0, default_zone.1);

        let errors = validate_bundle(&policies, &HashMap::new(), &zones, &HashMap::new());
        assert_eq!(errors.len(), 1);
        assert!(errors.iter().any(|err| {
            matches!(
                err,
                CheckError::BrokenReference(IntegrityError {
                    source_entity: "Policy",
                    field: "zone_pair_id",
                    missing_id,
                    ..
                }) if *missing_id == zp_id
            )
        }));
    }

    #[test]
    fn missing_zone_interface_ref_detected() {
        let z_id = Uuid::nil();
        let mut zones = HashMap::new();
        let (zid, zone) = create_test_zone(z_id, vec![Uuid::now_v7().to_string()]);
        zones.insert(zid, zone);

        let errors = validate_bundle(&HashMap::new(), &HashMap::new(), &zones, &HashMap::new());

        assert_eq!(errors.len(), 1);
        assert!(errors.iter().any(|err| {
            matches!(
                err,
                CheckError::BrokenReference(IntegrityError {
                    source_entity: "Zone",
                    field: "interface_ids",
                    target_type,
                    ..
                }) if *target_type == std::any::type_name::<ZoneInterfaceId>()
            )
        }));
    }

    #[test]
    fn non_uuid_zone_interface_ref_detected() {
        let z_id = Uuid::nil();
        let mut zones = HashMap::new();
        let (zid, zone) = create_test_zone(z_id, vec!["eth1".to_string()]);
        zones.insert(zid, zone);

        let errors = validate_bundle(&HashMap::new(), &HashMap::new(), &zones, &HashMap::new());

        assert_eq!(errors.len(), 1);
        assert!(errors.iter().any(|err| {
            matches!(
                err,
                CheckError::BrokenReference(IntegrityError {
                    source_entity: "Zone",
                    field: "interface_ids",
                    ..
                })
            )
        }));
    }

    #[test]
    fn missing_zone_ref_detected() {
        let z_id = Uuid::now_v7();
        let zp_id = Uuid::now_v7();

        let mut zone_pairs = HashMap::new();
        let (zpid, zp) = create_test_zone_pair(zp_id, z_id, z_id);
        zone_pairs.insert(zpid, zp);

        let default_zone = create_test_zone(Uuid::nil(), vec![]);
        let mut zones = HashMap::new();
        zones.insert(default_zone.0, default_zone.1);

        let errors = validate_bundle(&HashMap::new(), &zone_pairs, &zones, &HashMap::new());
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

        let default_zone = create_test_zone(Uuid::nil(), vec![]);
        let mut zones = HashMap::new();
        zones.insert(default_zone.0, default_zone.1);

        let errors = validate_bundle(&policies, &HashMap::new(), &zones, &zone_interfaces);
        assert_eq!(errors.len(), 2);
    }
}
