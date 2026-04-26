mod controller;
mod monitor;

pub use controller::{InterfaceController, InterfaceControllerError};
pub use monitor::{
    InterfaceMonitor, NetworkInterfaceMonitor, NetworkInterfaceMonitorError, OperState,
    SystemInterface, SystemInterfaceId,
};

#[cfg(test)]
pub use monitor::MockInterfaceMonitor;

