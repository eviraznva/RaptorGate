use crate::control_plane::errors::ipc_frame_error::IpcFrameError;

/// Rodzaj ramki przesyłanej przez lokalny protokół IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcFrameKind {
    Event = 1,
    Request = 2,
    Response = 3,
    Error = 4,
}

impl TryFrom<u32> for IpcFrameKind {
    type Error = IpcFrameError;

    fn try_from(value: u32) -> Result<Self, IpcFrameError> {
        match value {
            1 => Ok(Self::Event),
            2 => Ok(Self::Request),
            3 => Ok(Self::Response),
            4 => Ok(Self::Error),
            _ => Err(IpcFrameError::InvalidKind(value)),
        }
    }
}

impl From<IpcFrameKind> for u32 {
    fn from(value: IpcFrameKind) -> Self {
        value as u32
    }
}
