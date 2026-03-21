use std::io;
use std::fs;
use tracing::{debug, trace};
use std::collections::BTreeMap;

use nix::ifaddrs::getifaddrs;
use nix::net::if_::{InterfaceFlags, if_nametoindex};

use crate::control_plane::messages::responses::get_network_interfaces_response::NetworkInterfaceEntry;

/// Zwraca listę interfejsów widocznych dla procesu firewalla.
pub fn collect_interfaces() -> io::Result<Vec<NetworkInterfaceEntry>> {
    trace!("Collecting network interfaces for IPC response");
    
    let mut interfaces = BTreeMap::new();

    for address in getifaddrs().map_err(to_io_error)? {
        let name = address.interface_name;
        
        let entry = interfaces.entry(name.clone())
            .or_insert_with(|| NetworkInterfaceEntry {
                index: interface_index(&name).unwrap_or(0),
                is_up: false,
                mtu: interface_mtu(&name).unwrap_or(0),
                mac: Vec::new(),
                ips: Vec::new(),
                name,
            });

        entry.is_up |= address.flags.contains(InterfaceFlags::IFF_UP);

        if let Some(storage) = address.address {
            if let Some(link) = storage.as_link_addr() {
                if entry.mac.is_empty() {
                    if let Some(mac) = link.addr() {
                        if mac != [0; 6] {
                            entry.mac = mac.to_vec();
                        }
                    }
                }
            } else if let Some(inet) = storage.as_sockaddr_in() {
                push_unique_ip(&mut entry.ips, inet.ip().to_string());
            } else if let Some(inet6) = storage.as_sockaddr_in6() {
                push_unique_ip(&mut entry.ips, inet6.ip().to_string());
            }
        }
    }

    let interfaces: Vec<_> = interfaces.into_values().collect();

    debug!(interface_count = interfaces.len(), "Collected network interfaces");

    Ok(interfaces)
}

fn interface_index(name: &str) -> io::Result<u32> {
    trace!(interface = name, "Resolving interface index");
    
    if_nametoindex(name).map(|value| value as u32).map_err(to_io_error)
}

fn interface_mtu(name: &str) -> io::Result<u32> {
    let path = format!("/sys/class/net/{name}/mtu");

    trace!(interface = name, mtu_path = %path, "Resolving interface MTU");
    
    let raw = fs::read_to_string(path)?;
    
    parse_mtu(&raw)
}

fn parse_mtu(raw: &str) -> io::Result<u32> {
    raw.trim().parse::<u32>().map_err(|_| io::Error::other("failed to parse MTU value"))
}

fn push_unique_ip(ips: &mut Vec<String>, ip: String) {
    if !ips.iter().any(|existing| existing == &ip) {
        ips.push(ip);
    }
}

fn to_io_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(err.to_string())
}

#[cfg(test)]
mod interface_probe_tests {
    use super::{parse_mtu, push_unique_ip};

    #[test]
    fn parse_mtu_accepts_trimmed_decimal_value() {
        assert_eq!(parse_mtu("1500\n").unwrap(), 1500);
    }

    #[test]
    fn push_unique_ip_ignores_duplicates() {
        let mut ips = vec!["192.168.1.10".to_string()];

        push_unique_ip(&mut ips, "192.168.1.10".to_string());
        push_unique_ip(&mut ips, "fe80::1".to_string());

        assert_eq!(ips, vec!["192.168.1.10".to_string(), "fe80::1".to_string()]);
    }
}
