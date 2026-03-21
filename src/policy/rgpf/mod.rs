pub mod load;
pub mod errors;
pub mod endian;
pub mod sections;
pub mod constants;
pub mod validators;

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use crate::rule_tree::Verdict;
    use crate::policy::rgpf::sections::rgpf_file::RgpfFile;
    use crate::policy::rgpf::sections::rgpf_header::RgpfHeader;
    use crate::policy::rgpf::load::compiled_policy::load_compiled_policy;
    use crate::policy::rgpf::sections::nat::entries::NatRuleSectionHeader;
    use crate::frame::{Frame, Hour, IpVer, Octet, Port, Protocol, Weekday, IP};
    use crate::policy::rgpf::sections::rule_tree::entries::{RuleEntry, RuleNode, RuleTreeSectionHeader};

    use crate::policy::rgpf::constants::{
        NO_INDEX,
        VERDICT_DROP,
        NODE_KIND_MATCH,
        NODE_KIND_VERDICT,
        VERDICT_ALLOW_WARN,
        SECTION_STRING_TABLE,
        PATTERN_KIND_WILDCARD,
        SECTION_NAT_RULE_TABLE,
        SECTION_DEFAULT_VERDICT,
        SECTION_RULE_TREE_TABLE,
    };

    struct DummyFrame {
        src_ip: IP,
        dst_ip: IP,
        ip_ver: IpVer,
        protocol: Protocol,
        src_port: Option<Port>,
        dst_port: Option<Port>,
        hour: Hour,
        day_of_week: Weekday,
    }

    impl DummyFrame {
        fn tcp() -> Self {
            Self {
                src_ip: IP::new([Octet::Value(10), Octet::Value(0), Octet::Value(0), Octet::Value(1)]),
                dst_ip: IP::new([Octet::Value(10), Octet::Value(0), Octet::Value(0), Octet::Value(2)]),
                ip_ver: IpVer::V4,
                protocol: Protocol::Tcp,
                src_port: Some(Port::from(1234)),
                dst_port: Some(Port::from(80)),
                hour: Hour::try_from(12).unwrap(),
                day_of_week: Weekday::Mon,
            }
        }
    }

    impl Frame for DummyFrame {
        fn ip_ver(&self) -> IpVer { self.ip_ver }
        fn src_ip(&self) -> IP { self.src_ip }
        fn dst_ip(&self) -> IP { self.dst_ip }
        fn protocol(&self) -> Protocol { self.protocol }
        fn src_port(&self) -> Option<Port> { self.src_port }
        fn dst_port(&self) -> Option<Port> { self.dst_port }
        fn hour(&self) -> Hour { self.hour }
        fn day_of_week(&self) -> Weekday { self.day_of_week }
    }

    #[test]
    fn parses_minimal_rgpf_file() {
        let bytes = build_policy_bin(false);

        let file = RgpfFile::parse(&bytes).unwrap();

        assert_eq!(file.header().revision_id.get(), 7);
        assert_eq!(file.string_table().unwrap().get(0).unwrap(), "default");
        assert_eq!(file.rule_tree().unwrap().rules().len(), 1);
        assert!(file.nat_rules().unwrap().is_none());
    }

    #[test]
    fn loads_compiled_policy_from_rgpf() {
        let bytes = build_policy_bin(false);

        let file = RgpfFile::parse(&bytes).unwrap();

        let compiled = load_compiled_policy(&file).unwrap();

        assert_eq!(compiled.metadata().config_version, Some(7));
        assert_eq!(compiled.metadata().rule_count, 1);

        let verdict = compiled.evaluator().evaluate(&DummyFrame::tcp());

        assert_eq!(verdict, Some(Verdict::AllowWarn("allow-from-rgpf".into())));
    }

    #[test]
    fn parses_optional_nat_section() {
        let bytes = build_policy_bin(true);

        let file = RgpfFile::parse(&bytes).unwrap();

        assert!(file.nat_rules().unwrap().is_some());
        assert_eq!(file.nat_rules().unwrap().unwrap().rules().len(), 0);
    }

    fn build_policy_bin(include_nat: bool) -> Vec<u8> {
        let strings = build_string_table(&["default", "Loaded from RGPF", "allow-from-rgpf"]);

        let name_off = 0u32;

        let desc_off = string_entry_offset("default");

        let msg_off = desc_off + string_entry_len("Loaded from RGPF") as u32;

        let rule_tree = build_rule_tree_section(name_off, desc_off, msg_off);

        let default_verdict = build_default_verdict_section();

        let nat = if include_nat {
            Some(build_empty_nat_section())
        } else {
            None
        };

        let header_len = size_of::<RgpfHeader>();

        let section_count = if include_nat { 4u16 } else { 3u16 };

        let section_table_len = size_of::<crate::policy::rgpf::sections::section_table::SectionEntry>() * usize::from(section_count);

        let mut cursor = header_len + section_table_len;

        let string_offset = cursor;
        cursor += strings.len();

        let rule_tree_offset = cursor;
        cursor += rule_tree.len();

        let default_offset = cursor;
        cursor += default_verdict.len();

        let nat_offset = cursor;

        if let Some(ref nat_bytes) = nat {
            cursor += nat_bytes.len();
        }

        let mut bytes = Vec::with_capacity(cursor);

        bytes.resize(header_len, 0);

        let mut sections = Vec::new();

        sections.push(section_entry(SECTION_STRING_TABLE, string_offset, strings.len(), 3));
        sections.push(section_entry(SECTION_RULE_TREE_TABLE, rule_tree_offset, rule_tree.len(), 1));
        sections.push(section_entry(SECTION_DEFAULT_VERDICT, default_offset, default_verdict.len(), 1));

        if let Some(ref nat_bytes) = nat {
            sections.push(section_entry(SECTION_NAT_RULE_TABLE, nat_offset, nat_bytes.len(), 0));
        }

        for section in sections {
            bytes.extend_from_slice(&section);
        }

        bytes.extend_from_slice(&strings);
        bytes.extend_from_slice(&rule_tree);
        bytes.extend_from_slice(&default_verdict);

        if let Some(nat_bytes) = nat {
            bytes.extend_from_slice(&nat_bytes);
        }

        let total_len = bytes.len() as u64;

        write_header(
            &mut bytes[..header_len],
            section_count,
            header_len as u16,
            header_len as u64,
            total_len,
        );

        let crc = crc32c_with_zeroed_field(&bytes, file_crc32c_offset());

        let crc_offset = file_crc32c_offset();

        bytes[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());

        bytes
    }

    fn build_string_table(values: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();

        for value in values {
            bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }

        bytes
    }

    fn build_rule_tree_section(name_off: u32, desc_off: u32, msg_off: u32) -> Vec<u8> {
        let header_len = size_of::<RuleTreeSectionHeader>();

        let rules_offset = header_len as u64;

        let nodes_offset = rules_offset + size_of::<RuleEntry>() as u64;

        let object_arena_offset = nodes_offset + (2 * size_of::<RuleNode>()) as u64;

        let mut arena = Vec::new();
        arena.extend_from_slice(&0u32.to_le_bytes());

        let wildcard_off = arena.len() as u32;

        arena.push(PATTERN_KIND_WILDCARD);
        arena.push(0);
        arena.extend_from_slice(&0u16.to_le_bytes());

        let allow_verdict_off = arena.len() as u32;

        arena.push(VERDICT_ALLOW_WARN);
        arena.push(0);
        arena.extend_from_slice(&0u16.to_le_bytes());
        arena.extend_from_slice(&msg_off.to_le_bytes());

        let mut bytes = Vec::new();

        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&rules_offset.to_le_bytes());
        bytes.extend_from_slice(&nodes_offset.to_le_bytes());
        bytes.extend_from_slice(&object_arena_offset.to_le_bytes());
        bytes.extend_from_slice(&(arena.len() as u64).to_le_bytes());

        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&name_off.to_le_bytes());
        bytes.extend_from_slice(&desc_off.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        bytes.push(NODE_KIND_MATCH);
        bytes.push(crate::policy::rgpf::constants::MATCH_KIND_PROTOCOL);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&wildcard_off.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&NO_INDEX.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        bytes.push(NODE_KIND_VERDICT);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&NO_INDEX.to_le_bytes());
        bytes.extend_from_slice(&NO_INDEX.to_le_bytes());
        bytes.extend_from_slice(&allow_verdict_off.to_le_bytes());

        bytes.extend_from_slice(&arena);

        bytes
    }

    fn build_default_verdict_section() -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.push(VERDICT_DROP);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        bytes
    }

    fn build_empty_nat_section() -> Vec<u8> {
        let mut bytes = Vec::new();

        let header_len = size_of::<NatRuleSectionHeader>() as u64;

        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&header_len.to_le_bytes());
        bytes.extend_from_slice(&header_len.to_le_bytes());
        bytes.extend_from_slice(&header_len.to_le_bytes());
        bytes.extend_from_slice(&header_len.to_le_bytes());
        bytes.extend_from_slice(&header_len.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        bytes
    }

    fn section_entry(kind: u16, offset: usize, len: usize, item_count: u32) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(offset as u64).to_le_bytes());
        bytes.extend_from_slice(&(len as u64).to_le_bytes());
        bytes.extend_from_slice(&item_count.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        bytes
    }

    fn write_header(bytes: &mut [u8], section_count: u16, section_table_offset: u16, file_len: u64, computed_file_len: u64) {
        let mut cursor = 0usize;

        push_u32(bytes, &mut cursor, crate::policy::rgpf::constants::RGPF_MAGIC);
        push_u16(bytes, &mut cursor, 1);
        push_u16(bytes, &mut cursor, 0);
        push_u16(bytes, &mut cursor, size_of::<RgpfHeader>() as u16);
        push_u16(bytes, &mut cursor, section_count);
        push_u32(bytes, &mut cursor, 0);
        push_u64(bytes, &mut cursor, 7);
        push_u64(bytes, &mut cursor, 1700000000000);
        push_u64(bytes, &mut cursor, 0xABCDEF);
        push_u64(bytes, &mut cursor, u64::from(section_table_offset));
        push_u64(bytes, &mut cursor, computed_file_len.max(file_len));
        push_u32(bytes, &mut cursor, 0);
        push_u32(bytes, &mut cursor, 0);
    }

    fn push_u16(bytes: &mut [u8], cursor: &mut usize, value: u16) {
        bytes[*cursor..*cursor + 2].copy_from_slice(&value.to_le_bytes());

        *cursor += 2;
    }

    fn push_u32(bytes: &mut [u8], cursor: &mut usize, value: u32) {
        bytes[*cursor..*cursor + 4].copy_from_slice(&value.to_le_bytes());

        *cursor += 4;
    }

    fn push_u64(bytes: &mut [u8], cursor: &mut usize, value: u64) {
        bytes[*cursor..*cursor + 8].copy_from_slice(&value.to_le_bytes());

        *cursor += 8;
    }

    fn string_entry_offset(value: &str) -> u32 {
        string_entry_len(value) as u32
    }

    fn string_entry_len(value: &str) -> usize {
        4 + value.len()
    }

    fn file_crc32c_offset() -> usize {
        56
    }

    fn crc32c_with_zeroed_field(bytes: &[u8], field_offset: usize) -> u32 {
        let prefix = &bytes[..field_offset];
        
        let suffix = &bytes[field_offset + 4..];

        let mut crc = crc32c_update(!0u32, prefix);
        
        crc = crc32c_update(crc, &[0, 0, 0, 0]);
        crc = crc32c_update(crc, suffix);
        
        !crc
    }

    fn crc32c_update(mut crc: u32, bytes: &[u8]) -> u32 {
        for byte in bytes {
            crc ^= u32::from(*byte);
            
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0x82F63B78 & mask);
            }
        }

        crc
    }
}
