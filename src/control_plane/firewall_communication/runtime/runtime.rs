use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::policy::compiler;
use crate::policy::runtime::CompiledPolicy;
use crate::control_plane::firewall_communication::sync::listener;
use crate::control_plane::firewall_communication::publish::async_publisher;
use crate::control_plane::firewall_communication::config::FirewallIpcConfig;
use crate::control_plane::firewall_communication::runtime::state::{FirewallIpcStatus, FirewallState};

/// Handle do obserwacji stanu i polityki firewalla.
#[derive(Clone)]
pub struct FirewallIpcHandle {
    status_rx: watch::Receiver<FirewallIpcStatus>,
    policy_rx: watch::Receiver<Arc<CompiledPolicy>>,
}

impl FirewallIpcHandle {
    pub fn status(&self) -> watch::Receiver<FirewallIpcStatus> {
        self.status_rx.clone()
    }

    pub fn policy(&self) -> watch::Receiver<Arc<CompiledPolicy>> {
        self.policy_rx.clone()
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
        
        let (policy_tx, policy_rx) = 
            watch::channel(initial_policy.clone());
        
        let (status_tx, status_rx) = 
            watch::channel(FirewallIpcStatus::default());

        let state = FirewallState::new(policy_rx.clone());
        
        let status_state = state.clone();

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
            
            async move {
                async_publisher::run(config, state, shutdown).await;
            }
        });

        let status_join = tokio::spawn({
            let shutdown = shutdown.clone();
            
            async move {
                loop {
                    let snapshot = status_state.build_status_response().await;
                    
                    let next = FirewallIpcStatus {
                        mode: snapshot.mode,
                        loaded_revision_id: snapshot.loaded_revision_id,
                        last_error_code: snapshot.last_error_code,
                    };

                    if status_tx.send(next).is_err() {
                        return;
                    }

                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                    }
                }
            }
        });

        let _ = policy_tx;

        Ok(Self {
            handle: FirewallIpcHandle {
                status_rx,
                policy_rx,
            },
            shutdown,
            joins: vec![sync_join, async_join, status_join],
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
