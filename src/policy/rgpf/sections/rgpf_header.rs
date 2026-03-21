use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::policy::rgpf::endian::{LeU16, LeU32, LeU64};

/// Nagłówek pliku `RGPF/1` mapowany bez kopiowania z wejściowego bufora.
#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct RgpfHeader {
    pub magic: LeU32,
    pub major: LeU16,
    pub minor: LeU16,
    pub header_len: LeU16,
    pub section_count: LeU16,
    pub flags: LeU32,
    pub revision_id: LeU64,
    pub compiled_at_unix_ms: LeU64,
    pub policy_hash: LeU64,
    pub section_table_offset: LeU64,
    pub file_len: LeU64,
    pub file_crc32c: LeU32,
    pub reserved: LeU32,
}
