use std::collections::HashMap;
use std::sync::Arc;

use crate::interfaces::{InterfaceController, InterfaceControllerError};
use crate::zones::{resolve_os_name, ZoneInterface, ZoneInterfaceId, ZoneInterfaceKind};

#[derive(Debug, thiserror::Error)]
pub enum PhysicalReconciliationError {
    #[error("failed to update physical interface '{name}': {source}")]
    UpdateFailed {
        name: String,
        #[source]
        source: InterfaceControllerError,
    },
}

pub struct PhysicalInterfaceReconciler<IC: InterfaceController> {
    controller: Arc<IC>,
}

impl<IC: InterfaceController> PhysicalInterfaceReconciler<IC> {
    pub fn new(controller: Arc<IC>) -> Self {
        Self { controller }
    }

    pub async fn reconcile(
        &self,
        old: &HashMap<ZoneInterfaceId, ZoneInterface>,
        new: &HashMap<ZoneInterfaceId, ZoneInterface>,
    ) -> Vec<PhysicalReconciliationError> {
        let mut errors = Vec::new();

        for (id, new_zi) in new {
            let Some(old_zi) = old.get(id) else {
                continue;
            };

            let (ZoneInterfaceKind::Physical(old_physical), ZoneInterfaceKind::Physical(new_physical)) =
                (&old_zi.kind, &new_zi.kind)
            else {
                continue;
            };

            let rename = old_physical.interface_name != new_physical.interface_name;
            let address_changed = old_zi.addresses != new_zi.addresses;

            if rename || address_changed {
                let Some(old_name) = resolve_os_name(old, id) else {
                    continue;
                };

                let new_name = rename.then_some(new_physical.interface_name.as_str());
                let address = (new_zi.addresses.len() == 1).then_some(new_zi.addresses[0].as_str());

                if let Err(source) = self
                    .controller
                    .set_interface_properties(&old_name, new_name, address)
                    .await
                {
                    errors.push(PhysicalReconciliationError::UpdateFailed {
                        name: old_name,
                        source,
                    });
                }
            }
        }

        errors
    }
}
