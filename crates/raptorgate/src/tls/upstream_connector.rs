use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use thiserror::Error;
use tokio::net::{TcpSocket, TcpStream};

use crate::interfaces::{InterfaceMonitor, SystemInterfaceId};
use crate::netlink::routing_table::RoutingTable;
use crate::tls::inspection_relay::SessionMeta;

pub trait EgressRouteLookup: Send + Sync {
    fn route_lookup(&self, ip: IpAddr) -> Option<SystemInterfaceId>;
}

impl EgressRouteLookup for RoutingTable {
    fn route_lookup(&self, ip: IpAddr) -> Option<SystemInterfaceId> {
        RoutingTable::route_lookup(self, ip)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressInterface {
    pub interface_id: SystemInterfaceId,
    pub interface_name: String,
}

#[derive(Debug, Error)]
pub enum UpstreamConnectError {
    #[error("no route to upstream destination {dst}")]
    NoRoute { dst: IpAddr },
    #[error("egress interface {interface_id} is not present in interface monitor")]
    InterfaceMissing { interface_id: SystemInterfaceId },
    #[error("egress interface {interface_id} has empty name")]
    InterfaceNameEmpty { interface_id: SystemInterfaceId },
    #[error("failed to create upstream socket for {dst}")]
    SocketCreate { dst: SocketAddr, source: std::io::Error },
    #[error("failed to bind upstream socket to interface {interface_name}")]
    BindDevice { interface_name: String, source: std::io::Error },
    #[error("failed to connect upstream socket to {dst} via interface {interface_name}")]
    Connect { dst: SocketAddr, interface_name: String, source: std::io::Error },
}

#[tonic::async_trait]
pub trait UpstreamConnector: Send + Sync {
    async fn connect(
        &self,
        dst: SocketAddr,
        session_meta: &SessionMeta,
    ) -> Result<TcpStream, UpstreamConnectError>;
}

#[derive(Clone)]
pub struct LinuxUpstreamConnector {
    routing_table: Arc<dyn EgressRouteLookup>,
    interface_monitor: Arc<dyn InterfaceMonitor>,
}

impl LinuxUpstreamConnector {
    pub fn new(routing_table: Arc<RoutingTable>, interface_monitor: Arc<dyn InterfaceMonitor>) -> Self {
        Self {
            routing_table,
            interface_monitor,
        }
    }

    pub fn from_parts(
        routing_table: Arc<dyn EgressRouteLookup>,
        interface_monitor: Arc<dyn InterfaceMonitor>,
    ) -> Self {
        Self {
            routing_table,
            interface_monitor,
        }
    }

    pub fn resolve_egress(&self, dst: SocketAddr) -> Result<EgressInterface, UpstreamConnectError> {
        resolve_egress_interface(self.routing_table.as_ref(), self.interface_monitor.as_ref(), dst)
    }

    pub fn preflight_bind_device(interface_name: &str) -> std::io::Result<()> {
        let socket = TcpSocket::new_v4()?;
        bind_socket_to_interface(&socket, interface_name)
    }
}

#[tonic::async_trait]
impl UpstreamConnector for LinuxUpstreamConnector {
    async fn connect(
        &self,
        dst: SocketAddr,
        session_meta: &SessionMeta,
    ) -> Result<TcpStream, UpstreamConnectError> {
        let egress = match self.resolve_egress(dst) {
            Ok(egress) => egress,
            Err(err) => {
                tracing::error!(
                    event = "tls.upstream.connect.failed",
                    session_id = %session_meta.session_id,
                    dst = %dst,
                    mode = ?session_meta.mode,
                    sni = session_meta.sni.as_deref().unwrap_or(""),
                    error = %err,
                    "TLS upstream egress resolution failed"
                );
                return Err(err);
            }
        };

        tracing::info!(
            event = "tls.upstream.connect.started",
            session_id = %session_meta.session_id,
            dst = %dst,
            resolved_iface = %egress.interface_name,
            mode = ?session_meta.mode,
            sni = session_meta.sni.as_deref().unwrap_or(""),
            "TLS upstream connect started"
        );

        let stream = match connect_bound_socket(dst, &egress.interface_name).await {
            Ok(stream) => stream,
            Err(err) => {
                tracing::error!(
                    event = "tls.upstream.connect.failed",
                    session_id = %session_meta.session_id,
                    dst = %dst,
                    resolved_iface = %egress.interface_name,
                    mode = ?session_meta.mode,
                    sni = session_meta.sni.as_deref().unwrap_or(""),
                    error = %err,
                    "TLS upstream connect failed"
                );
                return Err(err);
            }
        };

        tracing::info!(
            event = "tls.upstream.connect.bound",
            session_id = %session_meta.session_id,
            dst = %dst,
            resolved_iface = %egress.interface_name,
            "TLS upstream socket bound and connected"
        );

        Ok(stream)
    }
}

pub fn resolve_egress_interface<R, M>(
    routing_table: &R,
    interface_monitor: &M,
    dst: SocketAddr,
) -> Result<EgressInterface, UpstreamConnectError>
where
    R: EgressRouteLookup + ?Sized,
    M: InterfaceMonitor + ?Sized,
{
    let Some(interface_id) = routing_table.route_lookup(dst.ip()) else {
        return Err(UpstreamConnectError::NoRoute { dst: dst.ip() });
    };
    let Some(interface) = interface_monitor.get_by_index(interface_id) else {
        return Err(UpstreamConnectError::InterfaceMissing { interface_id });
    };
    let interface_name = interface.name.trim();
    if interface_name.is_empty() {
        return Err(UpstreamConnectError::InterfaceNameEmpty { interface_id });
    }
    Ok(EgressInterface {
        interface_id,
        interface_name: interface_name.to_string(),
    })
}

async fn connect_bound_socket(
    dst: SocketAddr,
    interface_name: &str,
) -> Result<TcpStream, UpstreamConnectError> {
    let socket = create_socket(dst).map_err(|source| UpstreamConnectError::SocketCreate {
        dst,
        source,
    })?;
    bind_socket_to_interface(&socket, interface_name).map_err(|source| {
        UpstreamConnectError::BindDevice {
            interface_name: interface_name.to_string(),
            source,
        }
    })?;
    socket.connect(dst).await.map_err(|source| UpstreamConnectError::Connect {
        dst,
        interface_name: interface_name.to_string(),
        source,
    })
}

fn create_socket(dst: SocketAddr) -> std::io::Result<TcpSocket> {
    match dst {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
}

#[cfg(target_os = "linux")]
fn bind_socket_to_interface(socket: &TcpSocket, interface_name: &str) -> std::io::Result<()> {
    socket.bind_device(Some(interface_name.as_bytes()))
}

#[cfg(not(target_os = "linux"))]
fn bind_socket_to_interface(_socket: &TcpSocket, _interface_name: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SO_BINDTODEVICE requires Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interfaces::{MockInterfaceMonitor, OperState, SystemInterface};
    use mockall::predicate::eq;

    struct FakeRouteLookup {
        result: Option<SystemInterfaceId>,
    }

    impl EgressRouteLookup for FakeRouteLookup {
        fn route_lookup(&self, _ip: IpAddr) -> Option<SystemInterfaceId> {
            self.result
        }
    }

    fn iface(name: &str, index: SystemInterfaceId) -> SystemInterface {
        SystemInterface {
            index,
            name: name.to_string(),
            oper_state: OperState::Up,
            addresses: Vec::new(),
            vlan_id: None,
        }
    }

    #[test]
    fn resolve_egress_interface_uses_route_lookup_and_interface_monitor() {
        let if_id = SystemInterfaceId::from(7);
        let route_lookup = FakeRouteLookup {
            result: Some(if_id),
        };
        let mut monitor = MockInterfaceMonitor::new();
        monitor
            .expect_get_by_index()
            .with(eq(if_id))
            .return_once(move |_| Some(iface("wan0", if_id)));

        let dst = SocketAddr::from(([203, 0, 113, 10], 443));
        let resolved = resolve_egress_interface(&route_lookup, &monitor, dst).unwrap();

        assert_eq!(resolved.interface_id, if_id);
        assert_eq!(resolved.interface_name, "wan0");
    }

    #[test]
    fn resolve_egress_interface_fails_closed_without_route() {
        let route_lookup = FakeRouteLookup { result: None };
        let monitor = MockInterfaceMonitor::new();
        let dst = SocketAddr::from(([203, 0, 113, 10], 443));
        let err = resolve_egress_interface(&route_lookup, &monitor, dst).unwrap_err();

        assert!(matches!(err, UpstreamConnectError::NoRoute { .. }));
    }

    #[test]
    fn resolve_egress_interface_fails_closed_without_interface_record() {
        let if_id = SystemInterfaceId::from(9);
        let route_lookup = FakeRouteLookup {
            result: Some(if_id),
        };
        let mut monitor = MockInterfaceMonitor::new();
        monitor
            .expect_get_by_index()
            .with(eq(if_id))
            .return_once(|_| None);

        let dst = SocketAddr::from(([203, 0, 113, 10], 443));
        let err = resolve_egress_interface(&route_lookup, &monitor, dst).unwrap_err();

        assert!(matches!(err, UpstreamConnectError::InterfaceMissing { interface_id } if interface_id == if_id));
    }

    #[test]
    fn resolve_egress_interface_fails_closed_with_empty_interface_name() {
        let if_id = SystemInterfaceId::from(11);
        let route_lookup = FakeRouteLookup {
            result: Some(if_id),
        };
        let mut monitor = MockInterfaceMonitor::new();
        monitor
            .expect_get_by_index()
            .with(eq(if_id))
            .return_once(move |_| Some(iface("   ", if_id)));

        let dst = SocketAddr::from(([203, 0, 113, 10], 443));
        let err = resolve_egress_interface(&route_lookup, &monitor, dst).unwrap_err();

        assert!(matches!(err, UpstreamConnectError::InterfaceNameEmpty { interface_id } if interface_id == if_id));
    }
}
