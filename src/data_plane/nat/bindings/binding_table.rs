use std::net::IpAddr;
use std::time::Instant;
use std::collections::HashMap;

use crate::data_plane::nat::bindings::port_store::PortStore;

use crate::data_plane::nat::types::{
    FlowTuple, NatBinding, NatBindingDirection,
};

/// Struktura BindingTable przechowuje wszystkie aktywne powiązania NAT oraz indeksy umożliwiające szybkie wyszukiwanie translacji po flow.
/// Odpowiada za zarządzanie cyklem życia powiązań, ich wygaszanie oraz aktualizację portów.
pub struct BindingTable {
    bindings: HashMap<u64, NatBinding>,
    forward_index: HashMap<FlowTuple, u64>,
    reply_index: HashMap<FlowTuple, u64>,
    next_binding_id: u64,
}

impl BindingTable {
    /// Tworzy nową pustą tabelę powiązań NAT
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
            forward_index: HashMap::new(),
            reply_index: HashMap::new(),
            next_binding_id: 1,
        }
    }

    /// Zwraca kolejny dostępny identyfikator powiązania
    pub fn next_binding_id(&mut self) -> u64 {
        let next = self.next_binding_id;
        
        self.next_binding_id += 1;
        
        next
    }

    /// Wyszukuje powiązanie NAT dla danego flow
    pub fn lookup(&mut self, tuple: &FlowTuple) -> Option<(u64, NatBindingDirection)> {
        if let Some(binding_id) = self.forward_index.get(tuple).copied() {
            if let Some(binding) = self.bindings.get_mut(&binding_id) {
                binding.last_seen = Instant::now();
                return Some((binding_id, NatBindingDirection::Forward));
            }
        }

        if let Some(binding_id) = self.reply_index.get(tuple).copied() {
            if let Some(binding) = self.bindings.get_mut(&binding_id) {
                binding.last_seen = Instant::now();
                return Some((binding_id, NatBindingDirection::Reply));
            }
        }

        None
    }

    /// Dodaje nowe powiązanie NAT do tabeli i indeksów
    pub fn insert(&mut self, binding: NatBinding) {
        let binding_id = binding.binding_id;
        
        self.forward_index
            .insert(binding.original_forward.clone(), binding_id);
        
        self.reply_index
            .insert(binding.original_reply.clone(), binding_id);
        
        self.bindings.insert(binding_id, binding);
    }

    /// Zwraca referencję do powiązania o podanym ID
    pub fn get(&self, binding_id: u64) -> Option<&NatBinding> {
        self.bindings.get(&binding_id)
    }

    /// Wyszukuje prywatny adres IP na podstawie publicznego IP (np. do SNAT)
    pub fn find_private_ip_by_public(&self, public_ip: IpAddr) -> Option<IpAddr> {
        self.bindings.values()
            .find(|binding| binding.translated_forward.src_ip == public_ip)
            .map(|binding| binding.original_forward.src_ip)
    }

    /// Czyści wszystkie powiązania i indeksy
    pub fn clear(&mut self) {
        self.bindings.clear();
        self.forward_index.clear();
        self.reply_index.clear();
        
        self.next_binding_id = 1;
    }

    /// Usuwa powiązania, które wygasły oraz zwalnia porty
    pub fn expire_old_bindings(&mut self, port_store: &mut PortStore) {
        let now = Instant::now();
        
        let expired: Vec<u64> = self.bindings.iter()
            .filter_map(|(binding_id, binding)| {
                (binding.expires_at <= now).then_some(*binding_id)
            }).collect();

        for binding_id in expired {
            self.remove(binding_id, port_store);
        }
    }

    /// Usuwa powiązanie o podanym ID oraz zwalnia port
    fn remove(&mut self, binding_id: u64, port_store: &mut PortStore) {
        if let Some(binding) = self.bindings.remove(&binding_id) {
            self.forward_index.remove(&binding.original_forward);
            self.reply_index.remove(&binding.original_reply);

            if let Some(port) = binding.allocated_port {
                port_store.delete(
                    binding.translated_forward.src_ip,
                    binding.translated_forward.proto,
                    port,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use crate::data_plane::nat::bindings::{BindingTable, PortStore};
    use crate::data_plane::nat::types::{FlowTuple, L4Proto, NatBinding};
    use crate::policy::nat::port_range::PortRange;

    fn flow(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> FlowTuple {
        FlowTuple {
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
            src_port,
            dst_port,
            proto: L4Proto::Tcp,
        }
    }

    #[test]
    fn remove_cleans_reply_index() {
        let now = Instant::now();
        let original_forward = flow([10, 0, 0, 1], 1234, [1, 1, 1, 1], 21);
        let translated_forward = flow([192, 0, 2, 1], 40000, [1, 1, 1, 1], 21);
        let original_reply = translated_forward.reversed();
        let translated_reply = original_forward.reversed();

        let mut table = BindingTable::new();
        table.insert(NatBinding {
            binding_id: 1,
            rule_id: "rule".into(),
            original_forward,
            translated_forward,
            original_reply: original_reply.clone(),
            translated_reply,
            allocated_port: Some(40000),
            created_at: now,
            last_seen: now,
            expires_at: now - Duration::from_secs(1),
        });

        let mut ports = PortStore::new(PortRange::new(40000, 60000));
        table.expire_old_bindings(&mut ports);

        assert!(table.lookup(&original_reply).is_none());
    }
}
