use crate::control_plane::errors::ipc_frame_error::IpcFrameError;

/// Zestaw flag sterujących zachowaniem pojedynczej ramki IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcFrameFlags(u32);

impl IpcFrameFlags {
    pub const NONE: Self = Self(0);
    pub const ACK_REQUIRED: Self = Self(0x01);
    pub const CRITICAL: Self = Self(0x02);
    pub const NO_REPLY: Self = Self(0x04);

    const VALID_MASK: u32 = Self::ACK_REQUIRED.0 | Self::CRITICAL.0 | Self::NO_REPLY.0;

    /// Tworzy maskę bez walidacji bitów.
    pub const fn from_bits_unchecked(bits: u32) -> Self {
        Self(bits)
    }

    /// Zwraca surową reprezentację bitową flag.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Sprawdza, czy żaden bit nie jest ustawiony.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Sprawdza, czy bieżąca maska zawiera wszystkie bity z `other`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for IpcFrameFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for IpcFrameFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl TryFrom<u32> for IpcFrameFlags {
    type Error = IpcFrameError;

    fn try_from(value: u32) -> Result<Self, IpcFrameError> {
        if value & !Self::VALID_MASK != 0 {
            return Err(IpcFrameError::InvalidFlags(value));
        }

        Ok(Self(value))
    }
}

impl From<IpcFrameFlags> for u32 {
    fn from(value: IpcFrameFlags) -> Self {
        value.0
    }
}
