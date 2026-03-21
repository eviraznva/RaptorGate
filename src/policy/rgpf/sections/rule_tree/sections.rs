use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::policy::rgpf::endian::LeU32;
use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::section_table::SectionTable;

use crate::policy::rgpf::constants::{
    FIELD_VALUE_IP,
    PATTERN_KIND_OR,
    FIELD_VALUE_HOUR,
    FIELD_VALUE_PORT,
    PATTERN_KIND_GLOB,
    FIELD_VALUE_IP_VER,
    PATTERN_KIND_EQUAL,
    PATTERN_KIND_RANGE,
    FIELD_VALUE_PROTOCOL,
    PATTERN_KIND_WILDCARD,
    FIELD_VALUE_DAY_OF_WEEK,
    PATTERN_KIND_COMPARISON
};

use crate::policy::rgpf::sections::rule_tree::entries::{
    IpValue,
    RuleNode,
    HourValue,
    PortValue,
    RuleEntry,
    IpVerValue,
    GlobPattern,
    EqualPattern,
    VerdictEntry,
    RangePattern,
    ProtocolValue,
    DayOfWeekValue,
    FieldValueHeader,
    ComparisonPattern,
    PatternEntryHeader,
    RuleTreeSectionHeader
};

#[derive(Clone, Copy)]
pub struct RuleTreeSection<'a> {
    section: SectionTable<'a>,
    header: &'a RuleTreeSectionHeader,
    rules: &'a [RuleEntry],
    nodes: &'a [RuleNode],
    object_arena: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct DefaultVerdictSection<'a> {
    verdict: &'a VerdictEntry,
}

#[derive(Clone, Copy, Debug)]
pub enum FieldValueSection<'a> {
    Ip(&'a IpValue),
    IpVer(&'a IpVerValue),
    DayOfWeek(&'a DayOfWeekValue),
    Hour(&'a HourValue),
    Protocol(&'a ProtocolValue),
    Port(&'a PortValue),
}

#[derive(Clone, Copy, Debug)]
pub struct OrPatternSection<'a> {
    pattern_offsets: &'a [LeU32],
}

impl<'a> OrPatternSection<'a> {
    pub fn pattern_offsets(&self) -> &'a [LeU32] {
        self.pattern_offsets
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PatternSection<'a> {
    Wildcard,
    Equal(FieldValueSection<'a>),
    Glob(FieldValueSection<'a>),
    Range {
        lo: FieldValueSection<'a>,
        hi: FieldValueSection<'a>,
    },
    Comparison {
        op: u8,
        rhs: FieldValueSection<'a>,
    },
    Or(OrPatternSection<'a>),
}

impl<'a> RuleTreeSection<'a> {
    pub fn parse(section: SectionTable<'a>) -> Result<Self, RgpfError> {
        let header = RuleTreeSectionHeader::ref_from_prefix(section.bytes)
            .map_err(|_| RgpfError::InvalidLayout("invalid rule tree section header"))?
            .0;

        let rule_count = usize::try_from(header.rule_count.get()).map_err(|_| RgpfError::OffsetOutOfBounds)?;
        let node_count = usize::try_from(header.node_count.get()).map_err(|_| RgpfError::OffsetOutOfBounds)?;

        let rules = read_array::<RuleEntry>(section.bytes, header.rules_offset.get(), rule_count)?;

        let nodes = read_array::<RuleNode>(section.bytes, header.nodes_offset.get(), node_count)?;

        let object_arena = read_bytes(
            section.bytes,
            header.object_arena_offset.get(),
            header.object_arena_len.get(),
        )?;

        Ok(Self {
            section,
            header,
            rules,
            nodes,
            object_arena,
        })
    }

    pub fn section(&self) -> SectionTable<'a> {
        self.section
    }

    pub fn header(&self) -> &'a RuleTreeSectionHeader {
        self.header
    }

    pub fn rules(&self) -> &'a [RuleEntry] {
        self.rules
    }

    pub fn nodes(&self) -> &'a [RuleNode] {
        self.nodes
    }

    pub fn object_arena(&self) -> &'a [u8] {
        self.object_arena
    }

    pub fn node(&self, index: u32) -> Result<&'a RuleNode, RgpfError> {
        let index = usize::try_from(index).map_err(|_| RgpfError::OffsetOutOfBounds)?;

        self.nodes.get(index).ok_or(RgpfError::OffsetOutOfBounds)
    }

    pub fn pattern(&self, offset: u32) -> Result<PatternSection<'a>, RgpfError> {
        let header = read_struct::<PatternEntryHeader>(self.object_arena, u64::from(offset))?;

        match header.pattern_kind {
            PATTERN_KIND_WILDCARD => Ok(PatternSection::Wildcard),
            PATTERN_KIND_EQUAL => {
                let pattern = read_struct::<EqualPattern>(self.object_arena, u64::from(offset))?;

                Ok(PatternSection::Equal(self.field_value(pattern.field_value_off.get())?))
            }
            PATTERN_KIND_GLOB => {
                let pattern = read_struct::<GlobPattern>(self.object_arena, u64::from(offset))?;

                Ok(PatternSection::Glob(self.field_value(pattern.field_value_off.get())?))
            }
            PATTERN_KIND_RANGE => {
                let pattern = read_struct::<RangePattern>(self.object_arena, u64::from(offset))?;

                Ok(PatternSection::Range {
                    lo: self.field_value(pattern.lo_value_off.get())?,
                    hi: self.field_value(pattern.hi_value_off.get())?,
                })
            }
            PATTERN_KIND_COMPARISON => {
                let pattern = read_struct::<ComparisonPattern>(self.object_arena, u64::from(offset))?;

                Ok(PatternSection::Comparison {
                    op: pattern.op,
                    rhs: self.field_value(pattern.rhs_value_off.get())?,
                })
            }
            PATTERN_KIND_OR => {
                let start = usize::try_from(offset).map_err(|_| RgpfError::OffsetOutOfBounds)?;

                let count_bytes = self.object_arena.get(start
                        .checked_add(size_of::<PatternEntryHeader>()).ok_or(RgpfError::IntegerOverflow)?
                        ..start.checked_add(size_of::<PatternEntryHeader>() + 4)
                        .ok_or(RgpfError::IntegerOverflow)?
                ).ok_or(RgpfError::OffsetOutOfBounds)?;

                let count = u32::from_le_bytes(count_bytes.try_into().expect("exact count bytes"));

                let offsets_start = start.checked_add(size_of::<PatternEntryHeader>() + 4)
                    .ok_or(RgpfError::IntegerOverflow)?;

                let offsets = read_u32_array(self.object_arena, offsets_start, count)?;

                Ok(PatternSection::Or(OrPatternSection { pattern_offsets: offsets }))
            }
            value => Err(RgpfError::InvalidEnum {
                field: "pattern_kind",
                value: u64::from(value),
            }),
        }
    }

    pub fn field_value(&self, offset: u32) -> Result<FieldValueSection<'a>, RgpfError> {
        let header = read_struct::<FieldValueHeader>(self.object_arena, u64::from(offset))?;

        match header.type_tag {
            FIELD_VALUE_IP => Ok(FieldValueSection::Ip(read_struct::<IpValue>(self.object_arena, u64::from(offset))?)),
            FIELD_VALUE_IP_VER => Ok(FieldValueSection::IpVer(read_struct::<IpVerValue>(self.object_arena, u64::from(offset))?)),
            FIELD_VALUE_DAY_OF_WEEK => Ok(FieldValueSection::DayOfWeek(read_struct::<DayOfWeekValue>(self.object_arena, u64::from(offset))?)),
            FIELD_VALUE_HOUR => Ok(FieldValueSection::Hour(read_struct::<HourValue>(self.object_arena, u64::from(offset))?)),
            FIELD_VALUE_PROTOCOL => Ok(FieldValueSection::Protocol(read_struct::<ProtocolValue>(self.object_arena, u64::from(offset))?)),
            FIELD_VALUE_PORT => Ok(FieldValueSection::Port(read_struct::<PortValue>(self.object_arena, u64::from(offset))?)),
            value => Err(RgpfError::InvalidEnum {
                field: "field_value.type_tag",
                value: u64::from(value),
            }),
        }
    }

    pub fn verdict(&self, offset: u32) -> Result<&'a VerdictEntry, RgpfError> {
        read_struct::<VerdictEntry>(self.object_arena, u64::from(offset))
    }
}

impl<'a> DefaultVerdictSection<'a> {
    pub fn parse(section: SectionTable<'a>) -> Result<Self, RgpfError> {
        let verdict = VerdictEntry::ref_from_bytes(section.bytes)
            .map_err(|_| RgpfError::InvalidLayout("invalid default verdict layout"))?;

        Ok(Self { verdict })
    }

    pub fn verdict(&self) -> &'a VerdictEntry {
        self.verdict
    }
}

fn read_bytes(bytes: &[u8], offset: u64, len: u64) -> Result<&[u8], RgpfError> {
    let start = usize::try_from(offset).map_err(|_| RgpfError::OffsetOutOfBounds)?;

    let len = usize::try_from(len).map_err(|_| RgpfError::OffsetOutOfBounds)?;

    let end = start.checked_add(len).ok_or(RgpfError::IntegerOverflow)?;

    bytes.get(start..end).ok_or(RgpfError::OffsetOutOfBounds)
}

fn read_struct<T>(bytes: &[u8], offset: u64) -> Result<&T, RgpfError> where T: FromBytes + KnownLayout + Immutable {
    let start = usize::try_from(offset).map_err(|_| RgpfError::OffsetOutOfBounds)?;

    let end = start.checked_add(size_of::<T>()).ok_or(RgpfError::IntegerOverflow)?;

    let window = bytes.get(start..end).ok_or(RgpfError::OffsetOutOfBounds)?;

    T::ref_from_bytes(window).map_err(|_| RgpfError::InvalidLayout("invalid fixed-size object"))
}

fn read_array<T>(bytes: &[u8], offset: u64, count: usize) -> Result<&[T], RgpfError> where
    T: FromBytes + KnownLayout + Immutable,
{
    let size = size_of::<T>();

    let len = size.checked_mul(count).ok_or(RgpfError::IntegerOverflow)?;

    let start = usize::try_from(offset).map_err(|_| RgpfError::OffsetOutOfBounds)?;

    let end = start.checked_add(len).ok_or(RgpfError::IntegerOverflow)?;

    let window = bytes.get(start..end).ok_or(RgpfError::OffsetOutOfBounds)?;

    <[T]>::ref_from_bytes_with_elems(window, count).map_err(|_| RgpfError::InvalidLayout("invalid fixed-size array"))
}

fn read_u32_array(bytes: &[u8], start: usize, count: u32) -> Result<&[LeU32], RgpfError> {
    let count = usize::try_from(count).map_err(|_| RgpfError::OffsetOutOfBounds)?;

    let len = size_of::<LeU32>().checked_mul(count).ok_or(RgpfError::IntegerOverflow)?;

    let end = start.checked_add(len).ok_or(RgpfError::IntegerOverflow)?;

    let window = bytes.get(start..end).ok_or(RgpfError::OffsetOutOfBounds)?;

    <[LeU32]>::ref_from_bytes_with_elems(window, count).map_err(|_| RgpfError::InvalidLayout("invalid u32 array"))
}
