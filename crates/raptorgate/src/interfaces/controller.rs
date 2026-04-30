use std::net::IpAddr;
use std::sync::Arc;

use futures::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::Handle;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum InterfaceControllerError {
    #[error("failed to open netlink connection")]
    Connection(#[source] std::io::Error),
    #[error("interface '{0}' not found")]
    NotFound(String),
    #[error("netlink operation failed")]
    Netlink(#[source] rtnetlink::Error),
    #[error("invalid address '{0}'")]
    InvalidAddress(String),
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

pub async fn set_interface_properties(
  &self,
  name: &str,
  new_name: Option<&str>,
  address: Option<&str>,
) -> Result<String, InterfaceControllerError> {
  let index = self.get_interface_index(name).await?;
  let mut current_name = name.to_string();

  if let Some(new) = new_name {
    let message = rtnetlink::LinkUnspec::new_with_index(index)
      .name(new.to_string())
      .build();
    self.handle
      .link()
      .set(message)
      .execute()
      .await
      .map_err(InterfaceControllerError::Netlink)?;
    current_name = new.to_string();
  }

  if let Some(addr) = address {
    let ip_net: IpNet = addr
      .parse()
      .map_err(|_| InterfaceControllerError::InvalidAddress(addr.to_string()))?;
    let (ip, prefix_len) = match ip_net {
      IpNet::V4(v4) => (IpAddr::V4(v4.addr()), v4.prefix_len()),
      IpNet::V6(v6) => (IpAddr::V6(v6.addr()), v6.prefix_len()),
    };

    let existing = self.get_interface_addresses(index).await?;
    for existing_addr in existing {
      self.handle
        .address()
        .del(existing_addr)
        .execute()
        .await
        .map_err(InterfaceControllerError::Netlink)?;
    }

    self.handle
      .address()
      .add(index, ip, prefix_len)
      .execute()
      .await
      .map_err(InterfaceControllerError::Netlink)?;
  }

  Ok(current_name)
}

    async fn get_interface_index(&self, name: &str) -> Result<u32, InterfaceControllerError> {
        let mut links = self.handle.link().get().match_name(name.to_string()).execute();
        match links.try_next().await {
            Ok(Some(link)) => Ok(link.header.index),
            Ok(None) => Err(InterfaceControllerError::NotFound(name.to_string())),
            Err(e) => Err(InterfaceControllerError::Netlink(e)),
        }
    }

async fn get_interface_addresses(
        &self,
        index: u32,
    ) -> Result<Vec<netlink_packet_route::address::AddressMessage>, InterfaceControllerError> {
        let mut addresses = self.handle.address().get().execute();
        let mut result = Vec::new();
        while let Some(addr) = addresses
            .try_next()
            .await
            .map_err(InterfaceControllerError::Netlink)?
        {
            if addr.header.index == index {
                result.push(addr);
            }
        }
        Ok(result)
    }
}
