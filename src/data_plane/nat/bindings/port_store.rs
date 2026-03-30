use std::net::IpAddr;
use std::collections::HashSet;

use crate::data_plane::nat::types::L4Proto;
use crate::policy::nat::port_range::PortRange;

/// Struktura PortStore zarządza pulą portów używanych do translacji NAT (PAT).
/// Pozwala na przydzielanie i zwalnianie portów dla określonych adresów IP i protokołów,
/// zapewniając brak kolizji portów podczas translacji.
pub struct PortStore {
    leased_ports: HashSet<(IpAddr, L4Proto, u16)>,
    default_pat_pool: PortRange,
}

impl PortStore {
    /// Tworzy nowy PortStore z domyślną pulą portów PAT
    pub fn new(default_pat_pool: PortRange) -> Self {
        tracing::trace!(
            pool_start = default_pat_pool.start(),
            pool_end = default_pat_pool.end(),
            "nat port store initialized"
        );
        
        Self {
            leased_ports: HashSet::new(),
            default_pat_pool,
        }
    }

    /// Próbuje przydzielić port dla translacji NAT.
    /// Jeśli port oryginalny jest wolny, zostaje przydzielony.
    /// W przeciwnym razie szuka wolnego portu w zadanej puli.
    pub fn add(
        &mut self,
        public_ip: IpAddr,
        proto: L4Proto,
        original_port: u16,
        pool: Option<PortRange>,
    ) -> Option<u16> {
        if !proto.has_ports() {
            tracing::trace!(%public_ip, ?proto, original_port, "nat port allocation skipped for portless protocol");
            return Some(original_port);
        }

        let preferred = (public_ip, proto, original_port);
        
        if !self.leased_ports.contains(&preferred) {
            self.leased_ports.insert(preferred);
            tracing::debug!(%public_ip, ?proto, port = original_port, "nat port allocation reused original port");
            
            return Some(original_port);
        }

        let pool = pool.unwrap_or(self.default_pat_pool);
        
        tracing::trace!(
            %public_ip,
            ?proto,
            original_port,
            pool_start = pool.start(),
            pool_end = pool.end(),
            "nat port allocation searching fallback pool"
        );
        
        for port in pool.start()..=pool.end() {
            let candidate = (public_ip, proto, port);
            
            if !self.leased_ports.contains(&candidate) {
                self.leased_ports.insert(candidate);
                
                tracing::debug!(%public_ip, ?proto, allocated_port = port, "nat port allocation leased fallback port");
                
                return Some(port);
            }
        }

        tracing::warn!(%public_ip, ?proto, original_port, "nat port allocation exhausted");
        
        None
    }

    /// Zwalnia port przypisany do danego adresu IP i protokołu
    pub fn delete(&mut self, public_ip: IpAddr, proto: L4Proto, port: u16) {
        tracing::trace!(%public_ip, ?proto, port, "nat port allocation released");
        
        self.leased_ports.remove(&(public_ip, proto, port));
    }

    /// Czyści wszystkie przydzielone porty
    pub fn clear(&mut self) {
        tracing::debug!(leased_count = self.leased_ports.len(), "nat port store clear");
        
        self.leased_ports.clear();
    }
}
