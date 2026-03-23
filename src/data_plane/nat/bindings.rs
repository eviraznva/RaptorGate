use std::time::Instant;
use std::collections::HashMap;

use crate::data_plane::nat::port_store::PortStore;
use crate::data_plane::nat::types::flow_tuple::FlowTuple;
use crate::data_plane::nat::types::nat_binding::{NatBinding, NatBindingDirection};

pub struct BindingTable {
    bindings: HashMap<u64, NatBinding>,
    forward_index: HashMap<FlowTuple, u64>,
    reply_index: HashMap<FlowTuple, u64>,
    next_binding_id: u64,
}

impl BindingTable {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
            forward_index: HashMap::new(),
            reply_index: HashMap::new(),
            next_binding_id: 1,
        }
    }

    pub fn next_binding_id(&mut self) -> u64 {
        let next = self.next_binding_id;
        self.next_binding_id += 1;

        next
    }

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

    pub fn insert(&mut self, binding: NatBinding) {
        let binding_id = binding.binding_id;

        self.forward_index.insert(binding.original_forward.clone(), binding_id);
        self.reply_index.insert(binding.original_reply.clone(), binding_id);
        self.bindings.insert(binding_id, binding);
    }

    pub fn get(&self, binding_id: u64) -> Option<&NatBinding> {
        self.bindings.get(&binding_id)
    }

    pub fn clear(&mut self) {
        self.bindings.clear();
        self.forward_index.clear();
        self.reply_index.clear();

        self.next_binding_id = 1;
    }

    pub fn expire_old_bindings(&mut self, port_store: &mut PortStore) {
        let now = Instant::now();

        let expired: Vec<u64> = self.bindings.iter()
            .filter_map(|(binding_id, binding)| (binding.expires_at <= now).then_some(*binding_id))
            .collect();

        for binding_id in expired {
            self.remove(binding_id, port_store);
        }
    }

    fn remove(&mut self, binding_id: u64, port_store: &mut PortStore) {
        if let Some(binding) = self.bindings.remove(&binding_id) {
            self.forward_index.remove(&binding.original_forward);
            self.reply_index.remove(&binding.translated_reply);

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