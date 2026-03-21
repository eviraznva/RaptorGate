use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::policy::rgpf::endian::{LeU16, LeU32, LeU64};

#[derive(Clone, Copy)]
pub struct SectionTable<'a> {
    pub entry: &'a SectionEntry,
    pub bytes: &'a [u8],
}

impl<'a> SectionTable<'a> {
    pub fn kind(&self) -> u16 {
        self.entry.kind.get()
    }

    pub fn item_count(&self) -> u32 {
        self.entry.item_count.get()
    }
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct SectionEntry {
    pub kind: LeU16,
    pub flags: LeU16,
    pub offset: LeU64,
    pub length: LeU64,
    pub item_count: LeU32,
    pub reserved: LeU32,
    pub section_hash: LeU64,
}
