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
        
        let (connection, _handle, mut messages) = rtnetlink::new_multicast_connection(&groups)?;
        
        tokio::spawn(connection);
        
        let tx = sender.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    msg = messages.next() => {
                        if let Some((message, _)) = msg {
                            if let rtnetlink::packet_core::NetlinkPayload::InnerMessage(inner) = message.payload {
                                let _ = tx.send(inner);
                            }
                        } else {
                            break;
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
