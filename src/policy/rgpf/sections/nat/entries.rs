use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::policy::rgpf::endian::{LeU16, LeU32, LeU64};

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct NatRuleSectionHeader {
    pub rule_count: LeU32,
    pub match_count: LeU32,
    pub kind_count: LeU32,
    pub timeout_count: LeU32,
    pub rules_offset: LeU64,
    pub matches_offset: LeU64,
    pub kinds_offset: LeU64,
    pub timeouts_offset: LeU64,
    pub object_arena_offset: LeU64,
    pub object_arena_len: LeU64,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct NatRuleEntry {
    pub id_str_off: LeU32,
    pub name_str_off: LeU32,
    pub enabled: u8,
    pub applies_at: u8,
    pub reserved0: LeU16,
    pub priority: LeU32,
    pub match_index: LeU32,
    pub kind_index: LeU32,
    pub timeouts_index: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct NatMatchEntry {
    pub presence_bits: LeU32,
    pub in_interface_str_off: LeU32,
    pub out_interface_str_off: LeU32,
    pub in_zone_str_off: LeU32,
    pub out_zone_str_off: LeU32,
    pub src_cidr_off: LeU32,
    pub dst_cidr_off: LeU32,
    pub proto_off: LeU32,
    pub src_ports_off: LeU32,
    pub dst_ports_off: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct CidrEntry {
    pub ip_version: u8,
    pub prefix_len: u8,
    pub reserved0: LeU16,
    pub addr: [u8; 16],
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct NatProtoEntry {
    pub proto_kind: u8,
    pub reserved0: u8,
    pub reserved1: LeU16,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct PortRangeEntry {
    pub start: LeU16,
    pub end: LeU16,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct NatKindEntryHeader {
    pub kind_tag: u8,
    pub reserved0: u8,
    pub reserved1: LeU16,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct SnatKindEntry {
    pub header: NatKindEntryHeader,
    pub to_addr_off: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct MasqueradeKindEntry {
    pub header: NatKindEntryHeader,
    pub interface_str_off: LeU32,
    pub port_pool_off: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct DnatKindEntry {
    pub header: NatKindEntryHeader,
    pub to_addr_off: LeU32,
    pub to_port: LeU16,
    pub reserved0: LeU16,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct PatKindEntry {
    pub header: NatKindEntryHeader,
    pub to_addr_off: LeU32,
    pub interface_str_off: LeU32,
    pub port_pool_off: LeU32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct CidrAddressEntry {
    pub ip_version: u8,
    pub reserved0: u8,
    pub reserved1: LeU16,
    pub addr: [u8; 16],
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct NatTimeoutsEntry {
    pub presence_bits: u8,
    pub reserved0: u8,
    pub reserved1: LeU16,
    pub tcp_established_s: LeU64,
    pub udp_s: LeU64,
    pub icmp_s: LeU64,
}
