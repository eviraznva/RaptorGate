use std::collections::HashMap;
use std::sync::Arc;

use crate::interfaces::{InterfaceController, InterfaceControllerError};
use crate::zones::{resolve_os_name, ZoneInterface, ZoneInterfaceId, ZoneInterfaceKind};

#[derive(Debug, thiserror::Error)]
pub enum VlanReconciliationError {
    #[error("failed to create VLAN subinterface '{name}': {source}")]
    CreationFailed {
        name: String,
        #[source]
        source: InterfaceControllerError,
    },
    #[error("failed to delete VLAN subinterface '{name}': {source}")]
    DeletionFailed {
        name: String,
        #[source]
        source: InterfaceControllerError,
    },
    #[error("parent interface '{parent_id}' not found for VLAN subinterface")]
    ParentNotFound { parent_id: ZoneInterfaceId },
    #[error("failed to update addresses on VLAN subinterface '{name}': {source}")]
    AddressUpdateFailed {
        name: String,
        #[source]
        source: InterfaceControllerError,
    },
}

pub struct VlanReconciler<IC: InterfaceController> {
    controller: Arc<IC>,
}

impl<IC: InterfaceController> VlanReconciler<IC> {
    pub fn new(controller: Arc<IC>) -> Self {
        Self { controller }
    }

    pub async fn reconcile(
        &self,
        old: &HashMap<ZoneInterfaceId, ZoneInterface>,
        new: &HashMap<ZoneInterfaceId, ZoneInterface>,
    ) -> Vec<VlanReconciliationError> {
        let mut errors = Vec::new();

        // Deletion phase: VLANs in old but not in new, or where parent/vlan_id changed
        for (id, old_zi) in old {
            if let ZoneInterfaceKind::Vlan(old_vlan) = &old_zi.kind {
                let should_delete = match new.get(id) {
                    None => true,
                    Some(new_zi) => match &new_zi.kind {
                        ZoneInterfaceKind::Vlan(new_vlan) => {
                            old_vlan.parent_interface_id != new_vlan.parent_interface_id
                                || old_vlan.vlan_id != new_vlan.vlan_id
                        }
                        ZoneInterfaceKind::Physical(_) => true,
                    },
                };

                if should_delete {
                    if let Some(old_name) = resolve_os_name(old, id) {
                        if let Err(e) = self.controller.delete_vlan_subinterface(&old_name).await {
                            errors.push(VlanReconciliationError::DeletionFailed {
                                name: old_name,
                                source: e,
                            });
                        }
                    }
                }
            }
        }

        // Creation phase: VLANs in new but not in old, or where parent/vlan_id changed
        for (id, new_zi) in new {
            if let ZoneInterfaceKind::Vlan(new_vlan) = &new_zi.kind {
                let should_create = match old.get(id) {
                    None => true,
                    Some(old_zi) => match &old_zi.kind {
                        ZoneInterfaceKind::Vlan(old_vlan) => {
                            old_vlan.parent_interface_id != new_vlan.parent_interface_id
                                || old_vlan.vlan_id != new_vlan.vlan_id
                        }
                        ZoneInterfaceKind::Physical(_) => true,
                    },
                };

                if should_create {
                    let parent_name = match resolve_os_name(new, &new_vlan.parent_interface_id) {
                        Some(name) => name,
                        None => {
                            errors.push(VlanReconciliationError::ParentNotFound {
                                parent_id: new_vlan.parent_interface_id.clone(),
                            });
                            continue;
                        }
                    };

                    let vlan_name = match resolve_os_name(new, id) {
                        Some(name) => name,
                        None => continue,
                    };

                    if let Err(e) = self
                        .controller
                        .create_vlan_subinterface(
                            &parent_name,
                            new_vlan.vlan_id,
                            &vlan_name,
                            &new_zi.addresses,
                        )
                        .await
                    {
                        errors.push(VlanReconciliationError::CreationFailed {
                            name: vlan_name,
                            source: e,
                        });
                    }
                }
            }
        }

        // Address update phase: VLANs present in both with same parent/vlan_id but different addresses
        for (id, new_zi) in new {
            if let ZoneInterfaceKind::Vlan(new_vlan) = &new_zi.kind {
                if let Some(old_zi) = old.get(id) {
                    if let ZoneInterfaceKind::Vlan(old_vlan) = &old_zi.kind {
                        if old_vlan.parent_interface_id == new_vlan.parent_interface_id
                            && old_vlan.vlan_id == new_vlan.vlan_id
                            && old_zi.addresses != new_zi.addresses
                        {
                            if let Some(vlan_name) = resolve_os_name(new, id) {
                                for addr in &new_zi.addresses {
                                    if let Err(e) = self
                                        .controller
                                        .set_interface_properties(&vlan_name, None, Some(addr))
                                        .await
                                    {
                                        errors.push(VlanReconciliationError::AddressUpdateFailed {
                                            name: vlan_name.clone(),
                                            source: e,
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        errors
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::interfaces::MockInterfaceController;
    use crate::zones::{PhysicalInterface, VlanId, VlanSubinterface};
    use std::collections::HashMap;
    use uuid::Uuid;

    fn create_physical(name: &str) -> (ZoneInterfaceId, ZoneInterface) {
        let id = ZoneInterfaceId::from(Uuid::now_v7());
        let zi = ZoneInterface {
            zone_id: crate::zones::ZoneId::from(Uuid::now_v7()),
            kind: ZoneInterfaceKind::Physical(PhysicalInterface {
                interface_name: name.to_string(),
            }),
            status: crate::zones::InterfaceStatus::Unspecified,
            addresses: vec![],
            sniffed: false,
        };
        (id, zi)
    }

    fn create_vlan(
        parent_id: ZoneInterfaceId,
        vlan_id: u32,
        addresses: Vec<String>,
    ) -> (ZoneInterfaceId, ZoneInterface) {
        let id = ZoneInterfaceId::from(Uuid::now_v7());
        let zi = ZoneInterface {
            zone_id: crate::zones::ZoneId::from(Uuid::now_v7()),
            kind: ZoneInterfaceKind::Vlan(VlanSubinterface {
                parent_interface_id: parent_id,
                vlan_id: VlanId::try_from(vlan_id).unwrap(),
            }),
            status: crate::zones::InterfaceStatus::Unspecified,
            addresses,
            sniffed: false,
        };
        (id, zi)
    }

    #[tokio::test]
    async fn reconcile_creates_new_vlan() {
        let mut mock = MockInterfaceController::new();
        mock.expect_create_vlan_subinterface()
            .withf(|parent, vlan_id, name, addrs| {
                parent == "eth0" && u32::from(*vlan_id) == 100 && name == "eth0.100" && addrs.is_empty()
            })
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let reconciler = VlanReconciler::new(Arc::new(mock));

        let old = HashMap::new();
        let (parent_id, parent) = create_physical("eth0");
        let (vlan_id, vlan) = create_vlan(parent_id.clone(), 100, vec![]);
        let mut new = HashMap::new();
        new.insert(parent_id, parent);
        new.insert(vlan_id, vlan);

        let errors = reconciler.reconcile(&old, &new).await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn reconcile_creates_vlan_with_addresses() {
        let mut mock = MockInterfaceController::new();
        mock.expect_create_vlan_subinterface()
            .withf(|parent, vlan_id, name, addrs| {
                parent == "eth0"
                    && u32::from(*vlan_id) == 100
                    && name == "eth0.100"
                    && addrs == &["10.0.0.1/24"]
            })
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let reconciler = VlanReconciler::new(Arc::new(mock));

        let old = HashMap::new();
        let (parent_id, parent) = create_physical("eth0");
        let (vlan_id, vlan) = create_vlan(parent_id.clone(), 100, vec!["10.0.0.1/24".to_string()]);
        let mut new = HashMap::new();
        new.insert(parent_id, parent);
        new.insert(vlan_id, vlan);

        let errors = reconciler.reconcile(&old, &new).await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn reconcile_deletes_removed_vlan() {
        let mut mock = MockInterfaceController::new();
        mock.expect_delete_vlan_subinterface()
            .with(mockall::predicate::eq("eth0.100"))
            .times(1)
            .returning(|_| Ok(()));

        let reconciler = VlanReconciler::new(Arc::new(mock));

        let (parent_id, parent) = create_physical("eth0");
        let (vlan_id, vlan) = create_vlan(parent_id.clone(), 100, vec![]);
        let mut old = HashMap::new();
        old.insert(parent_id.clone(), parent.clone());
        old.insert(vlan_id, vlan);

        let mut new = HashMap::new();
        new.insert(parent_id, parent);

        let errors = reconciler.reconcile(&old, &new).await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn reconcile_noop_when_unchanged() {
        let mock = MockInterfaceController::new();
        let reconciler = VlanReconciler::new(Arc::new(mock));

        let (parent_id, parent) = create_physical("eth0");
        let (vlan_id, vlan) = create_vlan(parent_id.clone(), 100, vec![]);
        let mut old = HashMap::new();
        old.insert(parent_id.clone(), parent.clone());
        old.insert(vlan_id.clone(), vlan.clone());

        let mut new = HashMap::new();
        new.insert(parent_id, parent);
        new.insert(vlan_id, vlan);

        let errors = reconciler.reconcile(&old, &new).await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn reconcile_replaces_changed_vlan_id() {
        let mut mock = MockInterfaceController::new();
        mock.expect_delete_vlan_subinterface()
            .with(mockall::predicate::eq("eth0.100"))
            .times(1)
            .returning(|_| Ok(()));
        mock.expect_create_vlan_subinterface()
            .withf(|parent, vlan_id, name, addrs| {
                parent == "eth0" && u32::from(*vlan_id) == 200 && name == "eth0.200" && addrs.is_empty()
            })
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let reconciler = VlanReconciler::new(Arc::new(mock));

        let (parent_id, parent) = create_physical("eth0");
        let (vlan_id, vlan_old) = create_vlan(parent_id.clone(), 100, vec![]);
        let mut old = HashMap::new();
        old.insert(parent_id.clone(), parent.clone());
        old.insert(vlan_id.clone(), vlan_old);

        let (_, vlan_new) = create_vlan(parent_id.clone(), 200, vec![]);
        let mut new = HashMap::new();
        new.insert(parent_id, parent);
        new.insert(vlan_id, vlan_new);

        let errors = reconciler.reconcile(&old, &new).await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn reconcile_replaces_changed_parent() {
        let mut mock = MockInterfaceController::new();
        mock.expect_delete_vlan_subinterface()
            .with(mockall::predicate::eq("eth0.100"))
            .times(1)
            .returning(|_| Ok(()));
        mock.expect_create_vlan_subinterface()
            .withf(|parent, vlan_id, name, addrs| {
                parent == "eth1" && u32::from(*vlan_id) == 100 && name == "eth1.100" && addrs.is_empty()
            })
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let reconciler = VlanReconciler::new(Arc::new(mock));

        let (parent_a_id, parent_a) = create_physical("eth0");
        let (parent_b_id, parent_b) = create_physical("eth1");
        let (vlan_id, vlan_old) = create_vlan(parent_a_id.clone(), 100, vec![]);
        let mut old = HashMap::new();
        old.insert(parent_a_id, parent_a);
        old.insert(vlan_id.clone(), vlan_old);

        let (_, vlan_new) = create_vlan(parent_b_id.clone(), 100, vec![]);
        let mut new = HashMap::new();
        new.insert(parent_b_id, parent_b);
        new.insert(vlan_id, vlan_new);

        let errors = reconciler.reconcile(&old, &new).await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn reconcile_updates_addresses() {
        let mut mock = MockInterfaceController::new();
        mock.expect_set_interface_properties()
            .withf(|name, new_name, addr| {
                name == "eth0.100" && new_name.is_none() && addr == &Some("10.0.0.2/24")
            })
            .times(1)
            .returning(|_, _, _| Ok("eth0.100".to_string()));

        let reconciler = VlanReconciler::new(Arc::new(mock));

        let (parent_id, parent) = create_physical("eth0");
        let (vlan_id, vlan_old) = create_vlan(parent_id.clone(), 100, vec!["10.0.0.1/24".to_string()]);
        let mut old = HashMap::new();
        old.insert(parent_id.clone(), parent.clone());
        old.insert(vlan_id.clone(), vlan_old);

        let (_, vlan_new) = create_vlan(parent_id.clone(), 100, vec!["10.0.0.2/24".to_string()]);
        let mut new = HashMap::new();
        new.insert(parent_id, parent);
        new.insert(vlan_id, vlan_new);

        let errors = reconciler.reconcile(&old, &new).await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn reconcile_partial_failure_continues() {
        let mut mock = MockInterfaceController::new();
        mock.expect_create_vlan_subinterface()
            .withf(|parent, vlan_id, name, _| {
                parent == "eth0" && u32::from(*vlan_id) == 100 && name == "eth0.100"
            })
            .times(1)
            .returning(|_, _, _, _| Err(InterfaceControllerError::NotFound("eth0".to_string())));
        mock.expect_create_vlan_subinterface()
            .withf(|parent, vlan_id, name, _| {
                parent == "eth0" && u32::from(*vlan_id) == 200 && name == "eth0.200"
            })
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let reconciler = VlanReconciler::new(Arc::new(mock));

        let old = HashMap::new();
        let (parent_id, parent) = create_physical("eth0");
        let (vlan1_id, vlan1) = create_vlan(parent_id.clone(), 100, vec![]);
        let (vlan2_id, vlan2) = create_vlan(parent_id.clone(), 200, vec![]);
        let mut new = HashMap::new();
        new.insert(parent_id, parent);
        new.insert(vlan1_id, vlan1);
        new.insert(vlan2_id, vlan2);

        let errors = reconciler.reconcile(&old, &new).await;
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], VlanReconciliationError::CreationFailed { .. }));
    }

    #[tokio::test]
    async fn reconcile_parent_not_found() {
        let mut mock = MockInterfaceController::new();
        mock.expect_create_vlan_subinterface()
            .withf(|parent, vlan_id, name, _| {
                parent == "eth0" && u32::from(*vlan_id) == 200 && name == "eth0.200"
            })
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let reconciler = VlanReconciler::new(Arc::new(mock));

        let old = HashMap::new();
        let (parent_id, parent) = create_physical("eth0");
        let missing_parent_id = ZoneInterfaceId::from(Uuid::now_v7());
        let (vlan1_id, vlan1) = create_vlan(missing_parent_id, 100, vec![]);
        let (vlan2_id, vlan2) = create_vlan(parent_id.clone(), 200, vec![]);
        let mut new = HashMap::new();
        new.insert(parent_id, parent);
        new.insert(vlan1_id, vlan1);
        new.insert(vlan2_id, vlan2);

        let errors = reconciler.reconcile(&old, &new).await;
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], VlanReconciliationError::ParentNotFound { .. }));
    }

    #[tokio::test]
    async fn reconcile_ignores_physical_interfaces() {
        let mock = MockInterfaceController::new();
        let reconciler = VlanReconciler::new(Arc::new(mock));

        let (parent1_id, parent1) = create_physical("eth0");
        let (parent2_id, parent2) = create_physical("eth1");
        let mut old = HashMap::new();
        old.insert(parent1_id, parent1);

        let mut new = HashMap::new();
        new.insert(parent2_id, parent2);

        let errors = reconciler.reconcile(&old, &new).await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn reconcile_from_empty_on_startup() {
        let mut mock = MockInterfaceController::new();
        mock.expect_create_vlan_subinterface()
            .withf(|parent, vlan_id, name, _| {
                parent == "eth0" && u32::from(*vlan_id) == 100 && name == "eth0.100"
            })
            .times(1)
            .returning(|_, _, _, _| Ok(()));
        mock.expect_create_vlan_subinterface()
            .withf(|parent, vlan_id, name, _| {
                parent == "eth1" && u32::from(*vlan_id) == 200 && name == "eth1.200"
            })
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let reconciler = VlanReconciler::new(Arc::new(mock));

        let old = HashMap::new();
        let (parent1_id, parent1) = create_physical("eth0");
        let (parent2_id, parent2) = create_physical("eth1");
        let (vlan1_id, vlan1) = create_vlan(parent1_id.clone(), 100, vec![]);
        let (vlan2_id, vlan2) = create_vlan(parent2_id.clone(), 200, vec![]);
        let mut new = HashMap::new();
        new.insert(parent1_id, parent1);
        new.insert(parent2_id, parent2);
        new.insert(vlan1_id, vlan1);
        new.insert(vlan2_id, vlan2);

        let errors = reconciler.reconcile(&old, &new).await;
        assert!(errors.is_empty());
    }

    #[tokio::test]
    async fn reconcile_delete_orphan_not_in_new() {
        let mut mock = MockInterfaceController::new();
        mock.expect_delete_vlan_subinterface()
            .with(mockall::predicate::eq("eth0.100"))
            .times(1)
            .returning(|_| Ok(()));

        let reconciler = VlanReconciler::new(Arc::new(mock));

        let (parent_id, parent) = create_physical("eth0");
        let (vlan_id, vlan) = create_vlan(parent_id.clone(), 100, vec![]);
        let mut old = HashMap::new();
        old.insert(parent_id, parent);
        old.insert(vlan_id, vlan);

        let new = HashMap::new();

        let errors = reconciler.reconcile(&old, &new).await;
        assert!(errors.is_empty());
    }
}
