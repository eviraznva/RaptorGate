use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::policy::rgpf::endian::{LeU16, LeU32, LeU64};

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct RuleTreeSectionHeader {
    pub rule_count: LeU32,
    pub node_count: LeU32,
    pub verdict_count: LeU32,
    pub reserved0: LeU32,
    pub rules_offset: LeU64,
    pub nodes_offset: LeU64,
    pub object_arena_offset: LeU64,
    pub object_arena_len: LeU64,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct RuleEntry {
    pub rule_id: LeU32,
    pub name_str_off: LeU32,
    pub desc_str_off: LeU32,
    pub root_node_index: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct RuleNode {
    pub node_kind: u8,
    pub match_kind: u8,
    pub reserved0: LeU16,
    pub pattern_off: LeU32,
    pub yes_index: LeU32,
    pub no_index: LeU32,
    pub verdict_off: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct PatternEntryHeader {
    pub pattern_kind: u8,
    pub reserved0: u8,
    pub reserved1: LeU16,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct EqualPattern {
    pub header: PatternEntryHeader,
    pub field_value_off: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct GlobPattern {
    pub header: PatternEntryHeader,
    pub field_value_off: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct RangePattern {
    pub header: PatternEntryHeader,
    pub lo_value_off: LeU32,
    pub hi_value_off: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct ComparisonPattern {
    pub header: PatternEntryHeader,
    pub op: u8,
    pub reserved0: u8,
    pub reserved1: LeU16,
    pub rhs_value_off: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct FieldValueHeader {
    pub type_tag: u8,
    pub reserved0: u8,
    pub reserved1: LeU16,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct IpValue {
    pub header: FieldValueHeader,
    pub octet0: u8,
    pub octet1: u8,
    pub octet2: u8,
    pub octet3: u8,
    pub mask0: u8,
    pub mask1: u8,
    pub mask2: u8,
    pub mask3: u8,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct PortValue {
    pub header: FieldValueHeader,
    pub value: LeU16,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct HourValue {
    pub header: FieldValueHeader,
    pub value: u8,
    pub reserved: [u8; 3],
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct ProtocolValue {
    pub header: FieldValueHeader,
    pub value: u8,
    pub reserved: [u8; 3],
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct DayOfWeekValue {
    pub header: FieldValueHeader,
    pub value: u8,
    pub reserved: [u8; 3],
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct IpVerValue {
    pub header: FieldValueHeader,
    pub value: u8,
    pub reserved: [u8; 3],
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct VerdictEntry {
    pub verdict_kind: u8,
    pub reserved0: u8,
    pub reserved1: LeU16,
    pub message_str_off: LeU32,
}
