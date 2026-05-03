mod controller;
mod monitor;

pub use controller::{InterfaceController, InterfaceControllerError, NetlinkInterfaceController};
pub use monitor::{
    InterfaceMonitor, NetworkInterfaceMonitor, NetworkInterfaceMonitorError, OperState,
    SystemInterface, SystemInterfaceId,
};

#[cfg(test)]
pub use controller::MockInterfaceController;
#[cfg(test)]
pub use monitor::MockInterfaceMonitor;

