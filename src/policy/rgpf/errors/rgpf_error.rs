#[derive(Debug, thiserror::Error)]
pub enum RgpfError {
    #[error("invalid rgpf magic: {0:#010x}")]
    InvalidMagic(u32),

    #[error("unsupported rgpf version: {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },

    #[error("invalid header length: {0}")]
    InvalidHeaderLength(u16),

    #[error("invalid file length: declared {declared}, actual {actual}")]
    InvalidFileLength { declared: u64, actual: usize },

    #[error("invalid crc32c")]
    InvalidCrc32c,

    #[error("missing required section: {0}")]
    MissingSection(&'static str),

    #[error("duplicate section kind: {0}")]
    DuplicateSection(u16),

    #[error("invalid section: {0}")]
    InvalidSection(&'static str),

    #[error("section is out of bounds")]
    SectionOutOfBounds,

    #[error("offset is out of bounds")]
    OffsetOutOfBounds,

    #[error("integer overflow while validating layout")]
    IntegerOverflow,

    #[error("invalid utf-8 in rgpf section")]
    InvalidUtf8,

    #[error("invalid enum value for {field}: {value}")]
    InvalidEnum { field: &'static str, value: u64 },

    #[error("invalid boolean value: {0}")]
    InvalidBool(u8),

    #[error("invalid layout: {0}")]
    InvalidLayout(&'static str),

    #[error("unsupported layout: {0}")]
    UnsupportedLayout(&'static str),

    #[error("failed to compile policy source: {0}")]
    PolicyCompileFailed(String),
}
