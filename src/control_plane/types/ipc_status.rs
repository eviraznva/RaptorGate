use crate::control_plane::errors::ipc_frame_error::IpcFrameError;

/// Kod statusu odpowiedzi lub błędu zwracany w ramce IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpcStatus {
    Ok = 0,
    Accepted = 1,
    ErrBadMagic = 100,
    ErrUnsupportedVersion = 101,
    ErrBadFrame = 102,
    ErrBadPayloadLen = 103,
    ErrUnsupportedOpcode = 104,
    ErrMalformedPayload = 105,
    ErrInternal = 200,
    ErrPolicyNotLoaded = 201,
    ErrInterfaceEnumFailed = 202,
    ErrPolicyLoadFailed = 203,
    ErrPolicyRevisionMismatch = 204,
}

impl IpcStatus {
    /// Zwraca `true`, jeśli status oznacza odpowiedź sukcesu.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Ok | Self::Accepted)
    }
}

impl TryFrom<u32> for IpcStatus {
    type Error = IpcFrameError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Accepted),
            100 => Ok(Self::ErrBadMagic),
            101 => Ok(Self::ErrUnsupportedVersion),
            102 => Ok(Self::ErrBadFrame),
            103 => Ok(Self::ErrBadPayloadLen),
            104 => Ok(Self::ErrUnsupportedOpcode),
            105 => Ok(Self::ErrMalformedPayload),
            200 => Ok(Self::ErrInternal),
            201 => Ok(Self::ErrPolicyNotLoaded),
            202 => Ok(Self::ErrInterfaceEnumFailed),
            203 => Ok(Self::ErrPolicyLoadFailed),
            204 => Ok(Self::ErrPolicyRevisionMismatch),
            _ => Err(IpcFrameError::InvalidStatus(value)),
        }
    }
}

impl From<IpcStatus> for u32 {
    fn from(value: IpcStatus) -> Self {
        value as u32
    }
}

#[cfg(test)]
mod ipc_status_tests {
    use super::IpcStatus;
    use crate::control_plane::errors::ipc_frame_error::IpcFrameError;

    #[test]
    fn try_from_accepts_known_values() {
        assert_eq!(IpcStatus::try_from(0), Ok(IpcStatus::Ok));
        assert_eq!(IpcStatus::try_from(1), Ok(IpcStatus::Accepted));
        assert_eq!(
            IpcStatus::try_from(104),
            Ok(IpcStatus::ErrUnsupportedOpcode)
        );
        assert_eq!(
            IpcStatus::try_from(202),
            Ok(IpcStatus::ErrInterfaceEnumFailed)
        );
        assert_eq!(
            IpcStatus::try_from(203),
            Ok(IpcStatus::ErrPolicyLoadFailed)
        );
        assert_eq!(
            IpcStatus::try_from(204),
            Ok(IpcStatus::ErrPolicyRevisionMismatch)
        );
    }

    #[test]
    fn try_from_rejects_unknown_values() {
        assert_eq!(
            IpcStatus::try_from(999),
            Err(IpcFrameError::InvalidStatus(999))
        );
    }
}
