use std::convert::TryFrom;

pub mod raptorgate {
    pub mod common {
        tonic::include_proto!("raptorgate.common");
    }
    pub mod config {
        tonic::include_proto!("raptorgate.config");
    }
    pub mod events {
        tonic::include_proto!("raptorgate.events");
    }
    pub mod telemetry {
        tonic::include_proto!("raptorgate.telemetry");
    }

    tonic::include_proto!("raptorgate");
}

impl TryFrom<u8> for raptorgate::common::FirewallMode {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(raptorgate::common::FirewallMode::Unspecified),
            1 => Ok(raptorgate::common::FirewallMode::Normal),
            2 => Ok(raptorgate::common::FirewallMode::Emergency),
            3 => Ok(raptorgate::common::FirewallMode::SafeDeny),
            4 => Ok(raptorgate::common::FirewallMode::Resyncing),
            _ => Err(()),
        }
    }
}
