use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::policy::rgpf::endian::LeU32;
use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::section_table::SectionTable;

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct PolicyEntry {
    pub name_off: LeU32,
    pub priority: LeU32,
    pub source_off: LeU32,
    pub reserved: LeU32,
}

#[derive(Clone, Copy)]
pub struct PolicyEntryTable<'a> {
    entries: &'a [PolicyEntry],
}

impl<'a> PolicyEntryTable<'a> {
    pub fn parse(section: SectionTable<'a>) -> Result<Self, RgpfError> {
        let count = usize::try_from(section.item_count())
            .map_err(|_| RgpfError::OffsetOutOfBounds)?;

        let entries = <[PolicyEntry]>::ref_from_bytes_with_elems(section.bytes, count)
            .map_err(|_| RgpfError::InvalidLayout("invalid policy entry table layout"))?;

        Ok(Self { entries })
    }

    pub fn entries(&self) -> &'a [PolicyEntry] {
        self.entries
    }
}
