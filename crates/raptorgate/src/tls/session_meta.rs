use std::net::SocketAddr;

use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone)]
pub struct SessionMeta {
    pub session_id: Uuid,
    pub peer: SocketAddr,
    pub server: SocketAddr,
    pub sni: Option<String>,
    pub client_side_interface: Option<String>,
    pub server_side_interface: Option<String>,
    pub mode: InspectionMode,
}

impl SessionMeta {
    pub fn source_interface_for_direction(&self, direction: Direction) -> Option<&str> {
        match direction {
            Direction::ClientToServer => self.client_side_interface.as_deref(),
            Direction::ServerToClient => self.server_side_interface.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionMode {
    Outbound,
}
