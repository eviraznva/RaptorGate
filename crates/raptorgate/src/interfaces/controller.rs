use std::net::IpAddr;
use std::sync::Arc;

use futures::TryStreamExt;
use ipnet::IpNet;
use netlink_packet_route::link::{InfoData, InfoKind, InfoVlan, LinkAttribute, LinkInfo, LinkMessage};
use rtnetlink::Handle;
use thiserror::Error;

use crate::zones::VlanId;

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
    #[error("failed to create VLAN subinterface")]
    VlanCreationFailed(#[source] rtnetlink::Error),
    #[error("failed to delete VLAN subinterface")]
    VlanDeletionFailed(#[source] rtnetlink::Error),
}

#[cfg_attr(test, mockall::automock)]
#[tonic::async_trait]
pub trait InterfaceController: Send + Sync {
    async fn set_interface_state(&self, name: &str, up: bool) -> Result<(), InterfaceControllerError>;

    async fn set_interface_properties<'a>(
        &'a self,
        name: &'a str,
        new_name: Option<&'a str>,
        address: Option<&'a str>,
    ) -> Result<String, InterfaceControllerError>;

    async fn create_vlan_subinterface<'a>(
        &'a self,
        parent_name: &'a str,
        vlan_id: VlanId,
        subinterface_name: &'a str,
        addresses: &'a [String],
    ) -> Result<(), InterfaceControllerError>;

    async fn delete_vlan_subinterface<'a>(
        &'a self,
        subinterface_name: &'a str,
    ) -> Result<(), InterfaceControllerError>;
}

pub struct NetlinkInterfaceController {
    handle: Arc<Handle>,
}

impl NetlinkInterfaceController {
    pub fn new() -> Result<Self, InterfaceControllerError> {
        let (connection, handle, _) = rtnetlink::new_connection()
            .map_err(InterfaceControllerError::Connection)?;
        tokio::spawn(connection);
        Ok(Self { handle: Arc::new(handle) })
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

#[tonic::async_trait]
impl InterfaceController for NetlinkInterfaceController {
    async fn set_interface_state(&self, name: &str, up: bool) -> Result<(), InterfaceControllerError> {
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

    async fn set_interface_properties<'a>(
        &'a self,
        name: &'a str,
        new_name: Option<&'a str>,
        address: Option<&'a str>,
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

    async fn create_vlan_subinterface<'a>(
        &'a self,
        parent_name: &'a str,
        vlan_id: VlanId,
        subinterface_name: &'a str,
        addresses: &'a [String],
    ) -> Result<(), InterfaceControllerError> {
        let parsed_addresses: Vec<IpNet> = addresses
            .iter()
            .map(|addr| {
                addr.parse()
                    .map_err(|_| InterfaceControllerError::InvalidAddress(addr.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let parent_index = self.get_interface_index(parent_name).await?;

        let mut message = LinkMessage::default();
        message.attributes.push(LinkAttribute::IfName(subinterface_name.to_string()));
        message.attributes.push(LinkAttribute::Link(parent_index));
        message.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Vlan),
            LinkInfo::Data(InfoData::Vlan(vec![InfoVlan::Id(u32::from(vlan_id) as u16)])),
        ]));

        self.handle
            .link()
            .add(message)
            .execute()
            .await
            .map_err(InterfaceControllerError::VlanCreationFailed)?;

        self.set_interface_state(subinterface_name, true).await?;

        let subinterface_index = self.get_interface_index(subinterface_name).await?;
        for ip_net in parsed_addresses {
            let (ip, prefix_len) = match ip_net {
                IpNet::V4(v4) => (IpAddr::V4(v4.addr()), v4.prefix_len()),
                IpNet::V6(v6) => (IpAddr::V6(v6.addr()), v6.prefix_len()),
            };
            self.handle
                .address()
                .add(subinterface_index, ip, prefix_len)
                .execute()
                .await
                .map_err(InterfaceControllerError::VlanCreationFailed)?;
        }

        Ok(())
    }

    async fn delete_vlan_subinterface<'a>(
        &'a self,
        subinterface_name: &'a str,
    ) -> Result<(), InterfaceControllerError> {
        let index = self.get_interface_index(subinterface_name).await?;
        self.handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(InterfaceControllerError::VlanDeletionFailed)?;
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_interface_controller_create_vlan() {
        let mut mock = MockInterfaceController::new();
        mock.expect_create_vlan_subinterface()
            .withf(|parent, vlan_id, name, addrs| {
                parent == "eth0" && u32::from(*vlan_id) == 100 && name == "eth0.100" && addrs.is_empty()
            })
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let result = mock.create_vlan_subinterface("eth0", VlanId::try_from(100).unwrap(), "eth0.100", &[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_interface_controller_delete_vlan() {
        let mut mock = MockInterfaceController::new();
        mock.expect_delete_vlan_subinterface()
            .with(mockall::predicate::eq("eth0.100"))
            .times(1)
            .returning(|_| Ok(()));

        let result = mock.delete_vlan_subinterface("eth0.100").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_interface_controller_set_state() {
        let mut mock = MockInterfaceController::new();
        mock.expect_set_interface_state()
            .with(mockall::predicate::eq("eth0"), mockall::predicate::eq(true))
            .times(1)
            .returning(|_, _| Ok(()));

        let result = mock.set_interface_state("eth0", true).await;
        assert!(result.is_ok());
    }
}
