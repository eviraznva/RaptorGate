use crate::policy::rgpf::errors::rgpf_error::RgpfError;

#[derive(Clone, Copy)]
pub struct StringTable<'a> {
    bytes: &'a [u8],
}

impl<'a> StringTable<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Odczytuje string zapisany jako `u32 length + bytes[length]`.
    pub fn get(&self, offset: u32) -> Result<&'a str, RgpfError> {
        let start = usize::try_from(offset).map_err(|_| RgpfError::OffsetOutOfBounds)?;
        
        let len_end = start.checked_add(4).ok_or(RgpfError::IntegerOverflow)?;
        
        let len_bytes = self.bytes.get(start..len_end).ok_or(RgpfError::OffsetOutOfBounds)?;
        
        let len = u32::from_le_bytes(len_bytes.try_into().expect("exact 4 bytes"));
        
        let data_end = len_end
            .checked_add(usize::try_from(len).map_err(|_| RgpfError::OffsetOutOfBounds)?)
            .ok_or(RgpfError::IntegerOverflow)?;
        
        let data = self.bytes.get(len_end..data_end).ok_or(RgpfError::OffsetOutOfBounds)?;
        
        std::str::from_utf8(data).map_err(|_| RgpfError::InvalidUtf8)
    }
}
