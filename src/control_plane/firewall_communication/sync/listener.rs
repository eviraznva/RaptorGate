use std::path::Path;

use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

use crate::control_plane::firewall_communication::sync::session;
use crate::control_plane::firewall_communication::runtime::state::FirewallState;

/// Nasłuchuje na synchronicznym sockecie IPC i obsługuje kolejne połączenia.
pub async fn run(socket_path: String, state: FirewallState, shutdown: CancellationToken, ) 
    -> std::io::Result<()> 
{
    prepare_socket_path(&socket_path).await?;
    
    let listener = UnixListener::bind(&socket_path)?;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                cleanup_socket_path(&socket_path).await.ok();
                
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                
                tokio::spawn({
                    let state = state.clone();
                    
                    let shutdown = shutdown.clone();
                    
                    async move {
                        if let Err(err) = session::run(stream, state, shutdown).await {
                            tracing::warn!(error = %err, "IPC sync session failed");
                        }
                    }
                });
            }
        }
    }
}

async fn prepare_socket_path(socket_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(socket_path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    if Path::new(socket_path).exists() {
        let _ = tokio::fs::remove_file(socket_path).await;
    }

    Ok(())
}

async fn cleanup_socket_path(socket_path: &str) -> std::io::Result<()> {
    if Path::new(socket_path).exists() {
        tokio::fs::remove_file(socket_path).await?;
    }
    
    Ok(())
}
