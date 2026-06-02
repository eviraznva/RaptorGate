// WIP for smtp tracker

use std::net::IpAddr;

use unordered_pair::UnorderedPair;

use crate::proto::events::TcpEndpoint;
use crate::rule_tree::types::Port;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct TcpIdentifier {
    pub endpoints: UnorderedPair<EndpointIdentifier>,
}

impl TcpIdentifier {
    pub fn new(client: EndpointIdentifier, server: EndpointIdentifier) -> Self {
        Self {
            endpoints: UnorderedPair::from((client, server)),
        }
    }

    pub fn endpoints(&self) -> (EndpointIdentifier, EndpointIdentifier) {
        self.endpoints.clone().into_ordered_tuple()
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub struct EndpointIdentifier {
    pub ip: IpAddr,
    pub port: Port,
}

impl From<EndpointIdentifier> for TcpEndpoint {
    fn from(value: EndpointIdentifier) -> Self {
        TcpEndpoint {
            ip: value.ip.to_string(),
            port: u16::from(value.port) as u32,
        }
    }
}
