use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::policy::compiler;
use crate::control_plane::types::firewall_mode::FirewallMode;
use crate::control_plane::firewall_communication::sync::listener;
use crate::control_plane::firewall_communication::publish::async_publisher;
use crate::control_plane::firewall_communication::config::FirewallIpcConfig;
use crate::control_plane::firewall_communication::runtime::revision_store::RevisionStore;
use crate::control_plane::firewall_communication::publish::event_ring::{EventRingHandle, channel};

use crate::control_plane::firewall_communication::runtime::state::{
    ActiveRevision, FirewallState, FirewallRuntimeState
};

/// Handle do obserwacji stanu i polityki firewalla.
#[derive(Clone)]
pub struct FirewallIpcHandle {
    state_rx: watch::Receiver<Arc<FirewallRuntimeState>>,
    event_ring: EventRingHandle
}

impl FirewallIpcHandle {
    pub fn state(&self) -> watch::Receiver<Arc<FirewallRuntimeState>> {
        self.state_rx.clone()
    }

    pub fn event_ring(&self) -> EventRingHandle {
        self.event_ring.clone()
    }
}

/// Główny runtime firewall-side IPC.
pub struct FirewallIpcRuntime {
    handle: FirewallIpcHandle,
    shutdown: CancellationToken,
    joins: Vec<JoinHandle<()>>,
}

impl FirewallIpcRuntime {
    /// Uruchamia nowy runtime IPC firewalla.
    pub async fn start(config: FirewallIpcConfig, block_icmp: bool) 
        -> Result<Self, Box<dyn std::error::Error + Send + Sync>> 
    {
        let initial_policy = Arc::new(compiler::compile_fallback(block_icmp)?);

        let initial_revision = Arc::new(ActiveRevision::fallback(initial_policy.clone()));

        let initial_state = Arc::new(FirewallRuntimeState {
            mode: FirewallMode::Normal,
            active_revision: initial_revision.clone(),
            last_error_code: 0,
        });

        let (state_tx, state_rx) =
            watch::channel(initial_state);
        
        let (event_ring, event_rx) = channel(config.event_queue_capacity);

        let state = FirewallState::new(
            RevisionStore::new(config.config_store_path.clone()),
            state_tx,
        );

        let shutdown = CancellationToken::new();

        let sync_join = tokio::spawn({
            let state = state.clone();
            
            let shutdown = shutdown.clone();
            
            let socket_path = config.sync_socket_path.clone();
            
            async move {
                if let Err(err) = listener::run(socket_path, state, shutdown).await {
                    tracing::error!(error = %err, "Sync IPC listener stopped with error");
                }
            }
        });

        let async_join = tokio::spawn({
            let state = state.clone();
            
            let shutdown = shutdown.clone();
            
            let config = config.clone();
            let event_rx = event_rx;
            
            async move {
                async_publisher::run(config, state, event_rx, shutdown).await;
            }
        });

        Ok(Self {
            handle: FirewallIpcHandle {
                state_rx,
                event_ring,
            },
            shutdown,
            joins: vec![sync_join, async_join],
        })
    }

    pub fn handle(&self) -> FirewallIpcHandle {
        self.handle.clone()
    }

    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.shutdown.cancel();
        
        for join in self.joins {
            let _ = join.await;
        }
        
        Ok(())
    }
}
