use std::time::Duration;
use tokio::sync::broadcast;
use netlink_packet_route::RouteNetlinkMessage;
use rtnetlink::MulticastGroup;
use tokio_util::sync::CancellationToken;
use thiserror::Error;
use futures::StreamExt;

#[derive(Debug, Error)]
pub enum NetlinkError {
    #[error("failed to open netlink multicast connection")]
    MulticastConnection(#[from] std::io::Error),
}

#[derive(Clone)]
pub struct NetlinkListener {
    sender: broadcast::Sender<RouteNetlinkMessage>,
}

impl NetlinkListener {
    pub fn new(cancel: CancellationToken) -> Result<Self, NetlinkError> {
        let (sender, _) = broadcast::channel(1024);
        
        let groups = [
            MulticastGroup::Link,
            MulticastGroup::Ipv4Ifaddr,
            MulticastGroup::Ipv6Ifaddr,
            MulticastGroup::Ipv4Route,
            MulticastGroup::Ipv6Route,
        ];
        
        // Initial multicast socket open for startup fail-fast
        let (connection, _handle, messages) = rtnetlink::new_multicast_connection(&groups)?;
        
        tokio::spawn(connection);
        
        let tx = sender.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let mut messages = messages;
            let groups = [
                MulticastGroup::Link,
                MulticastGroup::Ipv4Ifaddr,
                MulticastGroup::Ipv6Ifaddr,
                MulticastGroup::Ipv4Route,
                MulticastGroup::Ipv6Route,
            ];

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    msg = messages.next() => {
                        match msg {
                            Some((message, _)) => {
                                if let rtnetlink::packet_core::NetlinkPayload::InnerMessage(inner) = message.payload {
                                    let _ = tx.send(inner);
                                }
                                // Reset backoff on any successful message as it indicates a healthy stream
                                backoff = Duration::from_secs(1);
                            }
                            None => {
                                tracing::warn!("Netlink multicast stream ended, entering reconnect loop");
                                
                                loop {
                                    tokio::select! {
                                        _ = cancel.cancelled() => return,
                                        _ = tokio::time::sleep(backoff) => {
                                            tracing::info!(
                                                backoff_secs = backoff.as_secs(),
                                                "Attempting to reconnect to netlink multicast"
                                            );
                                            match rtnetlink::new_multicast_connection(&groups) {
                                                Ok((conn, _handle, msgs)) => {
                                                    tokio::spawn(conn);
                                                    messages = msgs;
                                                    backoff = Duration::from_secs(1);
                                                    tracing::info!("Successfully reconnected to netlink multicast");
                                                    break; // Exit inner reconnect loop and resume outer listener loop
                                                }
                                                Err(err) => {
                                                    let next_backoff = next_backoff(backoff);
                                                    tracing::error!(
                                                        error = %err,
                                                        retry_delay_secs = next_backoff.as_secs(),
                                                        "Failed to reconnect to netlink multicast"
                                                    );
                                                    backoff = next_backoff;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        
        Ok(Self { sender })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RouteNetlinkMessage> {
        self.sender.subscribe()
    }
}

fn next_backoff(current: Duration) -> Duration {
    std::cmp::min(current * 2, Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_progression() {
        let b1 = Duration::from_secs(1);
        let b2 = next_backoff(b1);
        assert_eq!(b2, Duration::from_secs(2));
        
        let b3 = next_backoff(b2);
        assert_eq!(b3, Duration::from_secs(4));
        
        let b4 = next_backoff(Duration::from_secs(16));
        assert_eq!(b4, Duration::from_secs(30));
        
        let b5 = next_backoff(Duration::from_secs(30));
        assert_eq!(b5, Duration::from_secs(30));
    }
}
