pub const RGPF_MAGIC: u32 = u32::from_le_bytes(*b"RGPF");
pub const RGPF_MAJOR: u16 = 1;
pub const RGPF_MINOR: u16 = 0;
pub const NO_INDEX: u32 = u32::MAX;

pub const SECTION_STRING_TABLE: u16 = 1;
pub const SECTION_RULE_TREE_TABLE: u16 = 2;
pub const SECTION_DEFAULT_VERDICT: u16 = 3;
pub const SECTION_NAT_RULE_TABLE: u16 = 4;

pub const NODE_KIND_MATCH: u8 = 1;
pub const NODE_KIND_VERDICT: u8 = 2;

pub const PATTERN_KIND_WILDCARD: u8 = 1;
pub const PATTERN_KIND_EQUAL: u8 = 2;
pub const PATTERN_KIND_GLOB: u8 = 3;
pub const PATTERN_KIND_RANGE: u8 = 4;
pub const PATTERN_KIND_COMPARISON: u8 = 5;
pub const PATTERN_KIND_OR: u8 = 6;

pub const FIELD_VALUE_IP: u8 = 1;
pub const FIELD_VALUE_IP_VER: u8 = 2;
pub const FIELD_VALUE_DAY_OF_WEEK: u8 = 3;
pub const FIELD_VALUE_HOUR: u8 = 4;
pub const FIELD_VALUE_PROTOCOL: u8 = 5;
pub const FIELD_VALUE_PORT: u8 = 6;

pub const MATCH_KIND_SRC_IP: u8 = 1;
pub const MATCH_KIND_DST_IP: u8 = 2;
pub const MATCH_KIND_IP_VER: u8 = 3;
pub const MATCH_KIND_DAY_OF_WEEK: u8 = 4;
pub const MATCH_KIND_HOUR: u8 = 5;
pub const MATCH_KIND_PROTOCOL: u8 = 6;
pub const MATCH_KIND_SRC_PORT: u8 = 7;
pub const MATCH_KIND_DST_PORT: u8 = 8;

pub const COMPARISON_GREATER: u8 = 1;
pub const COMPARISON_LESSER: u8 = 2;
pub const COMPARISON_GREATER_OR_EQUAL: u8 = 3;
pub const COMPARISON_LESSER_OR_EQUAL: u8 = 4;

pub const VERDICT_ALLOW: u8 = 1;
pub const VERDICT_DROP: u8 = 2;
pub const VERDICT_ALLOW_WARN: u8 = 3;
pub const VERDICT_DROP_WARN: u8 = 4;

pub const IP_VER_V4: u8 = 1;
pub const IP_VER_V6: u8 = 2;

pub const PROTOCOL_TCP: u8 = 1;
pub const PROTOCOL_UDP: u8 = 2;
pub const PROTOCOL_ICMP: u8 = 3;

pub const WEEKDAY_MON: u8 = 1;
pub const WEEKDAY_TUE: u8 = 2;
pub const WEEKDAY_WED: u8 = 3;
pub const WEEKDAY_THU: u8 = 4;
pub const WEEKDAY_FRI: u8 = 5;
pub const WEEKDAY_SAT: u8 = 6;
pub const WEEKDAY_SUN: u8 = 7;

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
