/// Liczniki identyfikatorów używane przez endpointy IPC.
#[derive(Debug, Clone)]
pub struct IpcCounters {
    next_request_id: u64,
    next_sequence_no: u64,
}

impl Default for IpcCounters {
    fn default() -> Self {
        Self {
            next_request_id: 1,
            next_sequence_no: 1,
        }
    }
}

impl IpcCounters {
    /// Zwraca kolejny identyfikator żądania dla kanału request-response.
    pub fn next_request_id(&mut self) -> u64 {
        let value = self.next_request_id;
        
        self.next_request_id = self.next_request_id.saturating_add(1);

        tracing::trace!(request_id = value, next_request_id = self.next_request_id, "Allocated next IPC request id");
        
        value
    }

    /// Zwraca kolejny numer sekwencyjny wiadomości.
    pub fn next_sequence_no(&mut self) -> u64 {
        let value = self.next_sequence_no;
        
        self.next_sequence_no = self.next_sequence_no.saturating_add(1);

        tracing::trace!(sequence_no = value, next_sequence_no = self.next_sequence_no, "Allocated next IPC sequence number");
        
        value
    }
}
