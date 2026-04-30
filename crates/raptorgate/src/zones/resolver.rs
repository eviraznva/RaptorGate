use std::net::IpAddr;
use std::sync::Arc;

use crate::{
    interfaces::InterfaceMonitor,
    netlink::routing_table::RoutingTable,
    zones::{
        provider::{ZoneInterfaceProvider, ZonePairProvider},
        ResolvedZonePair,
    },
};

pub trait ZoneResolver: Send + Sync {
    fn resolve(&self, src_interface_name: &str, dst_ip: IpAddr) -> Option<ResolvedZonePair>;
}

#[derive(Clone)]
pub struct RoutingZoneResolver<M: InterfaceMonitor> {
    interface_provider: Arc<ZoneInterfaceProvider>,
    pair_provider: Arc<ZonePairProvider>,
    routing_table: Arc<RoutingTable>,
    interface_monitor: Arc<M>,
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
            .map(|(_, zi)| zi.zone_id)
            .unwrap_or_else(|| crate::zones::DEFAULT_ZONE_ID);

        let dst_zone_id = self
            .routing_table
            .route_lookup(dst_ip)
            .and_then(|idx| self.interface_monitor.get_by_index(idx))
            .and_then(|sys_iface| {
                self.interface_provider
                    .get_zone_interface_by_name(&sys_iface.name)
            })
            .map(|(_, zi)| zi.zone_id)
            .unwrap_or_else(|| crate::zones::DEFAULT_ZONE_ID);

        self.pair_provider
            .get_zone_pair_by_zones(&src_zone_id, &dst_zone_id)
            .map(|(id, pair)| ResolvedZonePair {
                id,
                default_policy: pair.default_policy,
            })
    }
}
