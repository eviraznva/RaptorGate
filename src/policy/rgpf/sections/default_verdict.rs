use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::policy::rgpf::endian::{LeU16, LeU32};
use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::section_table::SectionTable;

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct DefaultVerdictEntry {
    pub verdict_kind: u8,
    pub reserved0: u8,
    pub reserved1: LeU16,
    pub message_off: LeU32,
}

#[derive(Clone, Copy)]
pub struct DefaultVerdictSection<'a> {
    entry: &'a DefaultVerdictEntry,
}

impl<'a> DefaultVerdictSection<'a> {
    pub fn parse(section: SectionTable<'a>) -> Result<Self, RgpfError> {
        if section.bytes.len() != size_of::<DefaultVerdictEntry>() {
            return Err(RgpfError::InvalidLayout("invalid default verdict section length"));
        }

        let entry = DefaultVerdictEntry::ref_from_bytes(section.bytes)
            .map_err(|_| RgpfError::InvalidLayout("invalid default verdict layout"))?;

        Ok(Self { entry })
    }

    pub fn entry(&self) -> &'a DefaultVerdictEntry {
        self.entry
    }
}
