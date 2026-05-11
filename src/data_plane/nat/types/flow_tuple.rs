use std::net::IpAddr;

use super::l4_proto::L4Proto;

/// Struktura reprezentująca flow tuple połączenia sieciowego:
/// - src_ip: adres IP źródłowy
/// - dst_ip: adres IP docelowy
/// - src_port: port źródłowy
/// - dst_port: port docelowy
/// - proto: protokół warstwy 4 (TCP/UDP/ICMP)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: L4Proto,
}

impl FlowTuple {
    /// Zwraca nowy FlowTuple z zamienionymi stronami (przydatne do obsługi odpowiedzi)
    pub fn reversed(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            proto: self.proto,
        }
    }
}
