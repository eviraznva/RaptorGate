use crate::control_plane::errors::ipc_frame_error::IpcFrameError;

/// Kod operacji lub zdarzenia przesyłanego przez protokół IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpcOpcode {
    Ping = 0x01,
    GetStatus = 0x02,
    GetNetworkInterfaces = 0x03,
    Heartbeat = 0x100,
}

impl TryFrom<u32> for IpcOpcode {
    type Error = IpcFrameError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Ping),
            0x02 => Ok(Self::GetStatus),
            0x03 => Ok(Self::GetNetworkInterfaces),
            0x100 => Ok(Self::Heartbeat),
            _ => Err(IpcFrameError::InvalidOpcode(value)),
        }
    }
}

impl From<IpcOpcode> for u32 {
    fn from(value: IpcOpcode) -> Self {
        value as u32
    }
}

#[cfg(test)]
mod ipc_opcode_tests {
    use super::IpcOpcode;
    use crate::control_plane::errors::ipc_frame_error::IpcFrameError;

    #[test]
    fn try_from_accepts_known_values() {
        assert_eq!(IpcOpcode::try_from(0x01), Ok(IpcOpcode::Ping));
        assert_eq!(IpcOpcode::try_from(0x02), Ok(IpcOpcode::GetStatus));
        assert_eq!(
            IpcOpcode::try_from(0x03),
            Ok(IpcOpcode::GetNetworkInterfaces)
        );
        assert_eq!(IpcOpcode::try_from(0x100), Ok(IpcOpcode::Heartbeat));
    }

    #[test]
    fn try_from_rejects_unknown_values() {
        assert_eq!(
            IpcOpcode::try_from(0x999),
            Err(IpcFrameError::InvalidOpcode(0x999))
        );
    }
}
