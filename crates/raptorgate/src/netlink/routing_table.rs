use arc_swap::ArcSwap;
use std::sync::Arc;
use ipnet::IpNet;
use std::net::IpAddr;
use tokio::sync::broadcast;
use netlink_packet_route::{RouteNetlinkMessage, route::{RouteMessage, RouteAttribute}};
use tokio_util::sync::CancellationToken;
use futures::StreamExt;
use crate::netlink::listener::NetlinkListener;
use crate::interfaces::SystemInterfaceId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub destination: IpNet,
    pub out_interface_index: SystemInterfaceId,
    pub priority: u32,
}

pub struct RoutingTable {
    routes: ArcSwap<Vec<RouteEntry>>, 
}

impl RoutingTable {
    pub async fn new(
        listener: &NetlinkListener,
        cancel: CancellationToken
    ) -> anyhow::Result<Arc<Self>> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        
        let mut initial_routes = Vec::new();
        let mut routes_stream = handle.route().get(RouteMessage::default()).execute();
        
        while let Some(route) = routes_stream.next().await {
            let route = route?;
            if route.header.table == 254 { // Main table
                if let Some(entry) = Self::parse_route_message(&route) {
                    initial_routes.push(entry);
                }
            }
        }
        
        initial_routes.sort_by_key(|r| (r.destination.prefix_len(), -(r.priority as i64)));

        let table = Arc::new(Self { 
            routes: ArcSwap::from_pointee(initial_routes) 
        });
        
        let mut rx = listener.subscribe();
        let table_clone = Arc::clone(&table);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = rx.recv() => {
                        match result {
                            Ok(RouteNetlinkMessage::NewRoute(route)) => {
                                if route.header.table == 254 {
                                    table_clone.add_route(route);
                                }
                            }
                            Ok(RouteNetlinkMessage::DelRoute(route)) => {
                                if route.header.table == 254 {
                                    table_clone.remove_route(route);
                                }
                            }
                            Ok(_) => {}
                            Err(broadcast::error::RecvError::Lagged(count)) => {
                                tracing::warn!("RoutingTable netlink receiver lagged, missed {} messages", count);
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        });
        
        Ok(table)
    }

    fn parse_route_message(route: &RouteMessage) -> Option<RouteEntry> {
        let mut destination = None;
        let mut oif = None;
        let mut priority = 0;

        for attr in &route.attributes {
            match attr {
                RouteAttribute::Destination(addr) => {
                    let ip = match addr {
                        netlink_packet_route::route::RouteAddress::Inet(a) => IpAddr::V4(*a),
                        netlink_packet_route::route::RouteAddress::Inet6(a) => IpAddr::V6(*a),
                        _ => return None,
                    };
                    destination = Some(IpNet::new(ip, route.header.destination_prefix_length).ok()?);
                }
                RouteAttribute::Oif(index) => {
                    oif = Some(SystemInterfaceId::from(*index));
                }
                RouteAttribute::Priority(p) => {
                    priority = *p;
                }
                _ => {}
            }
        }

        // Default route handling (RTA_DST is missing)
        if destination.is_none() {
            let addr = match route.header.address_family {
                netlink_packet_route::AddressFamily::Inet => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                netlink_packet_route::AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                _ => return None,
            };
            destination = Some(IpNet::new(addr, 0).ok()?);
        }

        Some(RouteEntry {
            destination: destination?,
            out_interface_index: oif?,
            priority,
        })
    }

    fn add_route(&self, route: RouteMessage) {
        if let Some(new_entry) = Self::parse_route_message(&route) {
            self.routes.rcu(|routes| {
                let mut new_routes = (**routes).clone();
                // Remove existing if identical destination and priority
                new_routes.retain(|r| r.destination != new_entry.destination || r.priority != new_entry.priority);
                new_routes.push(new_entry.clone());
                new_routes.sort_by_key(|r| (r.destination.prefix_len(), -(r.priority as i64)));
                new_routes
            });
        }
    }

    fn remove_route(&self, route: RouteMessage) {
        if let Some(entry_to_remove) = Self::parse_route_message(&route) {
            self.routes.rcu(|routes| {
                let mut new_routes = (**routes).clone();
                new_routes.retain(|r| r.destination != entry_to_remove.destination || r.priority != entry_to_remove.priority);
                new_routes
            });
        }
    }

    pub fn route_lookup(&self, ip: IpAddr) -> Option<SystemInterfaceId> {
        let routes = self.routes.load();
        // Since routes is sorted by prefix_len (asc) and then priority (desc),
        // we should look for matches and take the one with highest prefix_len.
        // The sort order (prefix_len, -priority) means later entries are better matches.
        routes.iter()
            .filter(|r| r.destination.contains(&ip))
            .last()
            .map(|r| r.out_interface_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_route_lookup_lpm() {
        let routes = vec![
            RouteEntry {
                destination: "0.0.0.0/0".parse().unwrap(),
                out_interface_index: SystemInterfaceId::from(1),
                priority: 100,
            },
            RouteEntry {
                destination: "10.0.0.0/8".parse().unwrap(),
                out_interface_index: SystemInterfaceId::from(2),
                priority: 100,
            },
            RouteEntry {
                destination: "10.1.1.0/24".parse().unwrap(),
                out_interface_index: SystemInterfaceId::from(3),
                priority: 50,
            },
        ];
        
        let table = RoutingTable {
            routes: ArcSwap::from_pointee(routes),
        };

        // Exact match
        assert_eq!(table.route_lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 5))), Some(SystemInterfaceId::from(3)));
        // LPM match
        assert_eq!(table.route_lookup(IpAddr::V4(Ipv4Addr::new(10, 2, 2, 2))), Some(SystemInterfaceId::from(2)));
        // Default route
        assert_eq!(table.route_lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), Some(SystemInterfaceId::from(1)));
        // No match (IPv6 while only IPv4 routes)
        assert_eq!(table.route_lookup(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), None);
    }
    
    #[test]
    fn test_route_lookup_priority() {
        let mut routes = vec![
            RouteEntry {
                destination: "0.0.0.0/0".parse().unwrap(),
                out_interface_index: SystemInterfaceId::from(1),
                priority: 200,
            },
            RouteEntry {
                destination: "0.0.0.0/0".parse().unwrap(),
                out_interface_index: SystemInterfaceId::from(2),
                priority: 100,
            },
        ];
        // Sorted by (prefix_len, -priority)
        // (0, -200), (0, -100) -> [1, 2]
        routes.sort_by_key(|r| (r.destination.prefix_len(), -(r.priority as i64)));
        
        let table = RoutingTable {
            routes: ArcSwap::from_pointee(routes),
        };

        assert_eq!(table.route_lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), Some(SystemInterfaceId::from(2)));
    }
}
