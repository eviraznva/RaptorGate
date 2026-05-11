use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use uuid::Uuid;

use crate::interfaces::SystemInterface;
use crate::zones::{ZoneId, ZoneInterface};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressResolution {
    pub interface_name: String,
    pub zone_id: ZoneId,
    pub matched_prefix: IpNet,
}

pub fn resolve_zone_for_interface(
    interface_name: &str,
    zone_interfaces: &[ZoneInterface],
) -> Option<ZoneId> {
    zone_interfaces
        .iter()
        .find(|zone_interface| zone_interface.interface_name() == interface_name)
        .and_then(|zone_interface| assigned_zone_id(zone_interface.zone_id()))
}

pub fn resolve_egress_for_ip(
    dst_ip: IpAddr,
    live_interfaces: &HashMap<String, SystemInterface>,
    zone_interfaces: &[ZoneInterface],
) -> Option<EgressResolution> {
    zone_interfaces
        .iter()
        .filter_map(|zone_interface| {
            let zone_id = assigned_zone_id(zone_interface.zone_id())?;
            best_prefix_for_zone_interface(dst_ip, live_interfaces, zone_interface).map(|matched_prefix| EgressResolution {
                interface_name: zone_interface.interface_name().to_string(),
                zone_id,
                matched_prefix,
            })
        })
        .max_by_key(|resolution| resolution.matched_prefix.prefix_len())
}

fn assigned_zone_id(zone_id: &ZoneId) -> Option<ZoneId> {
    (Uuid::from(zone_id.clone()) != Uuid::nil()).then(|| zone_id.clone())
}

fn best_prefix_for_zone_interface(
    dst_ip: IpAddr,
    live_interfaces: &HashMap<String, SystemInterface>,
    zone_interface: &ZoneInterface,
) -> Option<IpNet> {
    let live_prefixes = live_interfaces
        .get(zone_interface.interface_name())
        .map(|interface| interface.addresses.as_slice())
        .unwrap_or_default();

    if !live_prefixes.is_empty() {
        return live_prefixes
            .iter()
            .copied()
            .filter(|prefix| prefix.contains(&dst_ip))
            .max_by_key(IpNet::prefix_len);
    }

    zone_interface
        .addresses
        .iter()
        .filter_map(|address| address.parse::<IpNet>().ok())
        .filter(|prefix| prefix.contains(&dst_ip))
        .max_by_key(IpNet::prefix_len)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ipnet::IpNet;
    use uuid::Uuid;

    use crate::interfaces::{OperState, SystemInterface, SystemInterfaceId};
    use crate::proto::config::{self, zone_interface};
    use crate::zones::ZoneInterface;

    use super::{resolve_egress_for_ip, resolve_zone_for_interface};

    fn system_interface(name: &str, addresses: &[&str]) -> SystemInterface {
        SystemInterface {
            index: SystemInterfaceId::from(1),
            name: name.to_string(),
            oper_state: OperState::Up,
            addresses: addresses
                .iter()
                .map(|address| address.parse::<IpNet>().unwrap())
                .collect(),
            vlan_id: None,
        }
    }

    fn zone_interface(zone_id: Uuid, name: &str, addresses: &[&str]) -> ZoneInterface {
        ZoneInterface::try_from_proto(crate::proto::config::ZoneInterface {
            id: Uuid::now_v7().to_string(),
            zone_id: zone_id.to_string(),
            status: crate::proto::config::InterfaceStatus::Active as i32,
            addresses: addresses.iter().map(|address| (*address).to_string()).collect(),
            kind: Some(zone_interface::Kind::Physical(config::PhysicalInterface {
                interface_name: name.to_string(),
            })),
            sniffed: false,
        })
        .unwrap()
        .1
    }

    #[test]
    fn resolves_non_lab_destination_from_live_interface_prefix() {
        let servers_zone_id = Uuid::now_v7();
        let interfaces = HashMap::from([(
            "wan10".to_string(),
            system_interface("wan10", &["10.88.0.1/24"]),
        )]);
        let zone_interfaces = vec![zone_interface(servers_zone_id, "wan10", &[])];

        let resolved =
            resolve_egress_for_ip("10.88.0.42".parse().unwrap(), &interfaces, &zone_interfaces)
                .expect("route resolved");

        assert_eq!(resolved.interface_name, "wan10");
        assert_eq!(Uuid::from(resolved.zone_id), servers_zone_id);
    }

    #[test]
    fn chooses_longest_prefix_match() {
        let broad_zone_id = Uuid::now_v7();
        let narrow_zone_id = Uuid::now_v7();
        let interfaces = HashMap::from([
            (
                "broad".to_string(),
                system_interface("broad", &["10.88.0.1/16"]),
            ),
            (
                "narrow".to_string(),
                system_interface("narrow", &["10.88.20.1/24"]),
            ),
        ]);
        let zone_interfaces = vec![
            zone_interface(broad_zone_id, "broad", &[]),
            zone_interface(narrow_zone_id, "narrow", &[]),
        ];

        let resolved =
            resolve_egress_for_ip("10.88.20.42".parse().unwrap(), &interfaces, &zone_interfaces)
                .expect("route resolved");

        assert_eq!(resolved.interface_name, "narrow");
        assert_eq!(Uuid::from(resolved.zone_id), narrow_zone_id);
    }

    #[test]
    fn ignores_interfaces_without_zone_assignment() {
        let interfaces = HashMap::from([(
            "unassigned".to_string(),
            system_interface("unassigned", &["10.88.0.1/24"]),
        )]);
        let zone_interfaces = vec![zone_interface(Uuid::nil(), "unassigned", &[])];

        let resolved =
            resolve_egress_for_ip("10.88.0.42".parse().unwrap(), &interfaces, &zone_interfaces);

        assert!(resolved.is_none());
    }

    #[test]
    fn falls_back_to_configured_zone_interface_addresses() {
        let servers_zone_id = Uuid::now_v7();
        let interfaces = HashMap::new();
        let zone_interfaces = vec![zone_interface(
            servers_zone_id,
            "protected0",
            &["10.99.0.1/24"],
        )];

        let resolved =
            resolve_egress_for_ip("10.99.0.42".parse().unwrap(), &interfaces, &zone_interfaces)
                .expect("route resolved");

        assert_eq!(resolved.interface_name, "protected0");
        assert_eq!(Uuid::from(resolved.zone_id), servers_zone_id);
    }

    #[test]
    fn resolves_source_zone_from_ingress_interface() {
        let clients_zone_id = Uuid::now_v7();
        let zone_interfaces = vec![zone_interface(clients_zone_id, "client9", &[])];

        let resolved =
            resolve_zone_for_interface("client9", &zone_interfaces).expect("zone resolved");

        assert_eq!(Uuid::from(resolved), clients_zone_id);
    }
}
