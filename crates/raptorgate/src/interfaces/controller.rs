use std::sync::Arc;

use futures::TryStreamExt;
use rtnetlink::Handle;
use thiserror::Error;

use super::monitor::SystemInterface;

#[derive(Debug, Error)]
pub enum InterfaceControllerError {
    #[error("failed to open netlink connection")]
    Connection(#[source] std::io::Error),
    #[error("interface '{0}' not found")]
    NotFound(String),
    #[error("netlink operation failed")]
    Netlink(#[source] rtnetlink::Error),
}

pub struct InterfaceController {
    handle: Arc<Handle>,
}

impl InterfaceController {
    pub fn new() -> Result<Self, InterfaceControllerError> {
        let (connection, handle, _) = rtnetlink::new_connection()
            .map_err(InterfaceControllerError::Connection)?;
        tokio::spawn(connection);
        Ok(Self { handle: Arc::new(handle) })
    }

    pub async fn set_interface_state(&self, name: &str, up: bool) -> Result<(), InterfaceControllerError> {
        let index = self.get_interface_index(name).await?;
        let message = if up {
            rtnetlink::LinkUnspec::new_with_index(index).up().build()
        } else {
            rtnetlink::LinkUnspec::new_with_index(index).down().build()
        };
        self.handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(InterfaceControllerError::Netlink)?;
        Ok(())
    }

    pub async fn rename_interface(&self, old_name: &str, new_name: &str) -> Result<(), InterfaceControllerError> {
        let index = self.get_interface_index(old_name).await?;
        let message = rtnetlink::LinkUnspec::new_with_index(index)
            .name(new_name.to_string())
            .build();
        self.handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(InterfaceControllerError::Netlink)?;
        Ok(())
    }

    async fn get_interface_index(&self, name: &str) -> Result<u32, InterfaceControllerError> {
        let mut links = self.handle.link().get().match_name(name.to_string()).execute();
        match links.try_next().await {
            Ok(Some(link)) => Ok(link.header.index),
            Ok(None) => Err(InterfaceControllerError::NotFound(name.to_string())),
            Err(e) => Err(InterfaceControllerError::Netlink(e)),
        }
    }
}
