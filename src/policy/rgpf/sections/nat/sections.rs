use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::section_table::SectionTable;

use crate::policy::rgpf::sections::nat::entries::{
    NatKindEntryHeader, NatRuleSectionHeader,
    NatRuleEntry, NatMatchEntry, NatTimeoutsEntry
};

#[derive(Clone, Copy)]
pub struct NatSection<'a> {
    section: SectionTable<'a>,
    header: &'a NatRuleSectionHeader,
    rules: &'a [NatRuleEntry],
    matches: &'a [NatMatchEntry],
    kinds: &'a [NatKindEntryHeader],
    timeouts: &'a [NatTimeoutsEntry],
    object_arena: &'a [u8],
}

impl<'a> NatSection<'a> {
    pub fn parse(section: SectionTable<'a>) -> Result<Self, RgpfError> {
        let header = NatRuleSectionHeader::ref_from_prefix(section.bytes)
            .map_err(|_| RgpfError::InvalidLayout("invalid nat section header"))?.0;

        let rule_count = usize::try_from(header.rule_count.get())
            .map_err(|_| RgpfError::OffsetOutOfBounds)?;
        
        let match_count = usize::try_from(header.match_count.get())
            .map_err(|_| RgpfError::OffsetOutOfBounds)?;
        
        let kind_count = usize::try_from(header.kind_count.get())
            .map_err(|_| RgpfError::OffsetOutOfBounds)?;
        
        let timeout_count = usize::try_from(header.timeout_count.get())
            .map_err(|_| RgpfError::OffsetOutOfBounds)?;

        let rules = 
            read_array::<NatRuleEntry>(section.bytes, header.rules_offset.get(), rule_count)?;
        
        let matches = 
            read_array::<NatMatchEntry>(section.bytes, header.matches_offset.get(), match_count)?;
        
        let kinds = 
            read_array::<NatKindEntryHeader>(section.bytes, header.kinds_offset.get(), kind_count)?;
        
        let timeouts = 
            read_array::<NatTimeoutsEntry>(section.bytes, header.timeouts_offset.get(), timeout_count)?;
        
        let object_arena = read_bytes(section.bytes,
            header.object_arena_offset.get(),
            header.object_arena_len.get()
        )?;

        Ok(Self {
            section,
            header,
            rules,
            matches,
            kinds,
            timeouts,
            object_arena,
        })
    }

    pub fn section(&self) -> SectionTable<'a> {
        self.section
    }

    pub fn header(&self) -> &'a NatRuleSectionHeader {
        self.header
    }

    pub fn rules(&self) -> &'a [NatRuleEntry] {
        self.rules
    }

    pub fn matches(&self) -> &'a [NatMatchEntry] {
        self.matches
    }

    pub fn kinds(&self) -> &'a [NatKindEntryHeader] {
        self.kinds
    }

    pub fn timeouts(&self) -> &'a [NatTimeoutsEntry] {
        self.timeouts
    }

    pub fn object_arena(&self) -> &'a [u8] {
        self.object_arena
    }
}

fn read_bytes(bytes: &[u8], offset: u64, len: u64) -> Result<&[u8], RgpfError> {
    let start = usize::try_from(offset).map_err(|_| RgpfError::OffsetOutOfBounds)?;
    
    let len = usize::try_from(len).map_err(|_| RgpfError::OffsetOutOfBounds)?;
    
    let end = start.checked_add(len).ok_or(RgpfError::IntegerOverflow)?;
    
    bytes.get(start..end).ok_or(RgpfError::OffsetOutOfBounds)
}

fn read_array<T>(bytes: &[u8], offset: u64, count: usize) -> Result<&[T], RgpfError> where
    T: FromBytes + KnownLayout + Immutable
{
    let size = size_of::<T>();
    
    let len = size.checked_mul(count).ok_or(RgpfError::IntegerOverflow)?;
    
    let start = usize::try_from(offset).map_err(|_| RgpfError::OffsetOutOfBounds)?;
    
    let end = start.checked_add(len).ok_or(RgpfError::IntegerOverflow)?;
    
    let window = bytes.get(start..end).ok_or(RgpfError::OffsetOutOfBounds)?;
    
    <[T]>::ref_from_bytes_with_elems(window, count)
        .map_err(|_| RgpfError::InvalidLayout("invalid nat fixed-size array"))
}
