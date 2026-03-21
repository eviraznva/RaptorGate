pub const RGPF_MAGIC: u32 = u32::from_le_bytes(*b"RGPF");
pub const RGPF_MAJOR: u16 = 1;
pub const RGPF_MINOR: u16 = 0;

pub const SECTION_POLICY_ENTRY_TABLE: u16 = 1;
pub const SECTION_POLICY_SOURCE_TABLE: u16 = 2;
pub const SECTION_DEFAULT_VERDICT: u16 = 3;
pub const SECTION_NAT_RULE_TABLE: u16 = 4;

pub const VERDICT_ALLOW: u8 = 1;
pub const VERDICT_DROP: u8 = 2;
pub const VERDICT_ALLOW_WARN: u8 = 3;
pub const VERDICT_DROP_WARN: u8 = 4;

pub const NAT_STAGE_PREROUTING: u8 = 1;
pub const NAT_STAGE_POSTROUTING: u8 = 2;

pub const NAT_PROTO_ANY: u8 = 1;
pub const NAT_PROTO_TCP: u8 = 2;
pub const NAT_PROTO_UDP: u8 = 3;
pub const NAT_PROTO_ICMP: u8 = 4;

pub const NAT_KIND_SNAT: u8 = 1;
pub const NAT_KIND_MASQUERADE: u8 = 2;
pub const NAT_KIND_DNAT: u8 = 3;
pub const NAT_KIND_PAT: u8 = 4;
