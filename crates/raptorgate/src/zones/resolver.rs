use std::net::IpAddr;
use std::sync::Arc;

use crate::{
    interfaces::InterfaceMonitor,
    netlink::routing_table::RoutingTable,
    zones::{
        provider::{ZoneInterfaceProvider, ZonePairProvider},
        DirectionalZonePairs, ResolvedZonePair,
    },
};

pub trait ZoneResolver: Send + Sync {
    fn resolve(&self, src_interface_name: &str, dst_ip: IpAddr) -> Option<ResolvedZonePair>;
    fn resolve_bidirectional(&self, src_ip: IpAddr, dst_ip: IpAddr) -> DirectionalZonePairs;
}

pub struct RoutingZoneResolver<M: InterfaceMonitor> {
    interface_provider: Arc<ZoneInterfaceProvider>,
    pair_provider: Arc<ZonePairProvider>,
    routing_table: Arc<RoutingTable>,
    interface_monitor: Arc<M>,
}

impl<M: InterfaceMonitor> Clone for RoutingZoneResolver<M> {
    fn clone(&self) -> Self {
        Self {
            interface_provider: Arc::clone(&self.interface_provider),
            pair_provider: Arc::clone(&self.pair_provider),
            routing_table: Arc::clone(&self.routing_table),
            interface_monitor: Arc::clone(&self.interface_monitor),
        }
    }
}

impl<M: InterfaceMonitor> RoutingZoneResolver<M> {
    pub fn new(
        interface_provider: Arc<ZoneInterfaceProvider>,
        pair_provider: Arc<ZonePairProvider>,
        routing_table: Arc<RoutingTable>,
        interface_monitor: Arc<M>,
    ) -> Self {
        Self {
            interface_provider,
            pair_provider,
            routing_table,
            interface_monitor,
        }
    }
}

impl<M: InterfaceMonitor> ZoneResolver for RoutingZoneResolver<M> {
    fn resolve(&self, src_interface_name: &str, dst_ip: IpAddr) -> Option<ResolvedZonePair> {
        let src_zone_id = self
            .interface_provider
            .get_zone_interface_by_name(src_interface_name)
            .map_or_else(|| crate::zones::DEFAULT_ZONE_ID, |(_, zi)| zi.zone_id);

        let dst_zone_id = self.zone_for_ip(dst_ip);

        self.pair_provider
            .get_zone_pair_by_zones(&src_zone_id, &dst_zone_id)
            .map(|(id, pair)| ResolvedZonePair {
                id,
                default_policy: pair.default_policy,
            })
    }

    fn resolve_bidirectional(&self, src_ip: IpAddr, dst_ip: IpAddr) -> DirectionalZonePairs {
        let src_zone_id = self.zone_for_ip(src_ip);
        let dst_zone_id = self.zone_for_ip(dst_ip);

        let forward = self
            .pair_provider
            .get_zone_pair_by_zones(&src_zone_id, &dst_zone_id)
            .map(|(id, pair)| ResolvedZonePair {
                id,
                default_policy: pair.default_policy,
            });

        let reverse = self
            .pair_provider
            .get_zone_pair_by_zones(&dst_zone_id, &src_zone_id)
            .map(|(id, pair)| ResolvedZonePair {
                id,
                default_policy: pair.default_policy,
            });

        DirectionalZonePairs { forward, reverse }
    }
}

impl<M: InterfaceMonitor> RoutingZoneResolver<M> {
    fn zone_for_ip(&self, ip: IpAddr) -> crate::zones::ZoneId {
        self.routing_table
            .route_lookup(ip)
            .and_then(|idx| self.interface_monitor.get_by_index(idx))
            .and_then(|sys_iface| {
                self.interface_provider
                    .get_zone_interface_by_name(&sys_iface.name)
            })
            .map_or_else(|| crate::zones::DEFAULT_ZONE_ID, |(_, zi)| zi.zone_id)
    }
}
