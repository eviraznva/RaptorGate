pub mod load;
pub mod errors;
pub mod endian;
pub mod sections;
pub mod constants;
pub mod validators;

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::mem::size_of;

    use crate::policy::rgpf::sections::rgpf_header::RgpfHeader;
    use crate::policy::rgpf::sections::section_table::SectionEntry;

    use crate::policy::rgpf::sections::nat::entries::{
        NatRuleEntry,
        NatMatchEntry,
        NatTimeoutsEntry,
        NatKindEntryHeader,
        NatRuleSectionHeader,
    };
    
    use crate::policy::rgpf::constants::{
        RGPF_MAGIC,
        RGPF_MAJOR,
        RGPF_MINOR,
        VERDICT_DROP,
        NAT_KIND_SNAT,
        VERDICT_ALLOW,
        VERDICT_DROP_WARN,
        VERDICT_ALLOW_WARN,
        NAT_STAGE_PREROUTING,
        SECTION_NAT_RULE_TABLE,
        SECTION_DEFAULT_VERDICT,
        SECTION_POLICY_ENTRY_TABLE,
        SECTION_POLICY_SOURCE_TABLE,
    };

    pub const TEST_POLICY_HASH: u64 = 0xABCD_EF12_3456_7890;
    pub const TEST_POLICY_NAME: &str = "default";
    pub const TEST_POLICY_SOURCE: &str =
        "match protocol { = tcp : verdict allow_warn \"allow-from-rgpf\" }";

    #[derive(Clone, Copy)]
    pub struct TestPolicyEntry<'a> {
        pub name: &'a str,
        pub priority: u32,
        pub dsl_source: &'a str,
    }

    #[derive(Clone, Copy)]
    pub enum TestDefaultVerdict<'a> {
        Allow,
        Drop,
        AllowWarn(&'a str),
        DropWarn(&'a str),
    }

    pub fn build_policy_bin(revision_id: u64, policy_source: &str) -> Vec<u8> {
        build_policy_bundle_bin(
            revision_id,
            &[TestPolicyEntry {
                name: TEST_POLICY_NAME,
                priority: 0,
                dsl_source: policy_source,
            }],
            TestDefaultVerdict::Drop,
        )
    }

    pub fn build_policy_bundle_bin(
        revision_id: u64,
        policies: &[TestPolicyEntry<'_>],
        default_verdict: TestDefaultVerdict<'_>,
    ) -> Vec<u8> {
        build_policy_bin_internal(revision_id, TEST_POLICY_HASH, policies, default_verdict, None)
    }

    pub fn build_policy_bin_with_empty_nat(revision_id: u64, policy_source: &str) -> Vec<u8> {
        build_policy_bin_internal(
            revision_id,
            TEST_POLICY_HASH,
            &[TestPolicyEntry {
                name: TEST_POLICY_NAME,
                priority: 0,
                dsl_source: policy_source,
            }],
            TestDefaultVerdict::Drop,
            Some(build_empty_nat_section()),
        )
    }

    pub fn build_policy_bin_with_invalid_nat(revision_id: u64, policy_source: &str) -> Vec<u8> {
        build_policy_bin_internal(
            revision_id,
            TEST_POLICY_HASH,
            &[TestPolicyEntry {
                name: TEST_POLICY_NAME,
                priority: 0,
                dsl_source: policy_source,
            }],
            TestDefaultVerdict::Drop,
            Some(build_invalid_nat_section()),
        )
    }

    fn build_policy_bin_internal(
        revision_id: u64,
        policy_hash: u64,
        policies: &[TestPolicyEntry<'_>],
        default_verdict: TestDefaultVerdict<'_>,
        nat_section: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let mut policy_source_table = Vec::new();
        let mut policy_entries = Vec::with_capacity(policies.len());

        for policy in policies {
            let name_off = push_string_entry(&mut policy_source_table, policy.name);
            let source_off = push_string_entry(&mut policy_source_table, policy.dsl_source);

            policy_entries.push((name_off, policy.priority, source_off));
        }

        let default_verdict_section =
            build_default_verdict_section(&mut policy_source_table, default_verdict);

        let header_len = size_of::<RgpfHeader>();
        let section_count = if nat_section.is_some() { 4u16 } else { 3u16 };
        let section_table_len = size_of::<SectionEntry>() * usize::from(section_count);

        let mut cursor = header_len + section_table_len;

        let policy_entry_table_offset = cursor;
        let policy_entry_table_len = policy_entries.len() * 16;
        cursor += policy_entry_table_len;

        let policy_source_table_offset = cursor;
        cursor += policy_source_table.len();

        let default_verdict_offset = cursor;
        cursor += default_verdict_section.len();

        let nat_offset = cursor;

        if let Some(ref nat_bytes) = nat_section {
            cursor += nat_bytes.len();
        }

        let mut bytes = Vec::with_capacity(cursor);
        bytes.resize(header_len, 0);

        let mut sections = vec![
            section_entry(
                SECTION_POLICY_ENTRY_TABLE,
                policy_entry_table_offset,
                policy_entry_table_len,
                policy_entries.len() as u32,
            ),
            section_entry(
                SECTION_POLICY_SOURCE_TABLE,
                policy_source_table_offset,
                policy_source_table.len(),
                count_policy_source_items(policies, default_verdict),
            ),
            section_entry(
                SECTION_DEFAULT_VERDICT,
                default_verdict_offset,
                default_verdict_section.len(),
                1,
            ),
        ];

        if let Some(ref nat_bytes) = nat_section {
            sections.push(section_entry(
                SECTION_NAT_RULE_TABLE,
                nat_offset,
                nat_bytes.len(),
                0,
            ));
        }

        for section in sections {
            bytes.extend_from_slice(&section);
        }

        for (name_off, priority, source_off) in policy_entries {
            bytes.extend_from_slice(&name_off.to_le_bytes());
            bytes.extend_from_slice(&priority.to_le_bytes());
            bytes.extend_from_slice(&source_off.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }

        bytes.extend_from_slice(&policy_source_table);
        bytes.extend_from_slice(&default_verdict_section);

        if let Some(nat_bytes) = nat_section {
            bytes.extend_from_slice(&nat_bytes);
        }

        let total_len = bytes.len() as u64;

        write_header(
            &mut bytes[..header_len],
            revision_id,
            policy_hash,
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

    fn count_policy_source_items(
        policies: &[TestPolicyEntry<'_>],
        default_verdict: TestDefaultVerdict<'_>,
    ) -> u32 {
        let mut count = (policies.len() * 2) as u32;

        if matches!(
            default_verdict,
            TestDefaultVerdict::AllowWarn(_) | TestDefaultVerdict::DropWarn(_)
        ) {
            count += 1;
        }

        count
    }

    fn build_default_verdict_section(
        policy_source_table: &mut Vec<u8>,
        default_verdict: TestDefaultVerdict<'_>,
    ) -> Vec<u8> {
        let (verdict_kind, message_off) = match default_verdict {
            TestDefaultVerdict::Allow => (VERDICT_ALLOW, 0),
            TestDefaultVerdict::Drop => (VERDICT_DROP, 0),
            TestDefaultVerdict::AllowWarn(message) => {
                (VERDICT_ALLOW_WARN, push_string_entry(policy_source_table, message))
            }
            TestDefaultVerdict::DropWarn(message) => {
                (VERDICT_DROP_WARN, push_string_entry(policy_source_table, message))
            }
        };

        let mut bytes = Vec::with_capacity(8);
        bytes.push(verdict_kind);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&message_off.to_le_bytes());
        bytes
    }

    fn push_string_entry(table: &mut Vec<u8>, value: &str) -> u32 {
        let offset = table.len() as u32;
        table.extend_from_slice(&(value.len() as u32).to_le_bytes());
        table.extend_from_slice(value.as_bytes());
        offset
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

    fn build_invalid_nat_section() -> Vec<u8> {
        let header_len = size_of::<NatRuleSectionHeader>();
        let rules_offset = header_len as u64;
        let matches_offset = rules_offset + size_of::<NatRuleEntry>() as u64;
        let kinds_offset = matches_offset + size_of::<NatMatchEntry>() as u64;
        let timeouts_offset = kinds_offset + size_of::<NatKindEntryHeader>() as u64;
        let object_arena_offset = timeouts_offset + size_of::<NatTimeoutsEntry>() as u64;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&rules_offset.to_le_bytes());
        bytes.extend_from_slice(&matches_offset.to_le_bytes());
        bytes.extend_from_slice(&kinds_offset.to_le_bytes());
        bytes.extend_from_slice(&timeouts_offset.to_le_bytes());
        bytes.extend_from_slice(&object_arena_offset.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(2);
        bytes.push(NAT_STAGE_PREROUTING);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        bytes.push(NAT_KIND_SNAT);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());

        bytes.push(0);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
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

    fn write_header(
        bytes: &mut [u8],
        revision_id: u64,
        policy_hash: u64,
        section_count: u16,
        header_len: u16,
        section_table_offset: u64,
        file_len: u64,
    ) {
        let mut cursor = 0usize;

        push_u32(bytes, &mut cursor, RGPF_MAGIC);
        push_u16(bytes, &mut cursor, RGPF_MAJOR);
        push_u16(bytes, &mut cursor, RGPF_MINOR);
        push_u16(bytes, &mut cursor, header_len);
        push_u16(bytes, &mut cursor, section_count);
        push_u32(bytes, &mut cursor, 0);
        push_u64(bytes, &mut cursor, revision_id);
        push_u64(bytes, &mut cursor, 1_700_000_000_000);
        push_u64(bytes, &mut cursor, policy_hash);
        push_u64(bytes, &mut cursor, section_table_offset);
        push_u64(bytes, &mut cursor, file_len);
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
        for &byte in bytes {
            crc ^= u32::from(byte);

            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0x82F63B78 & mask);
            }
        }

        crc
    }
}

#[cfg(test)]
mod tests {
    use crate::rule_tree::Verdict;
    use crate::policy::rgpf::constants::VERDICT_DROP;
    use crate::policy::rgpf::sections::rgpf_file::RgpfFile;
    use crate::policy::rgpf::load::compiled_policy::load_compiled_policy_bundle;
    use crate::policy::rgpf::test_helpers::{
        build_policy_bin,
        build_policy_bin_with_empty_nat,
        build_policy_bin_with_invalid_nat,
        build_policy_bundle_bin,
        TestDefaultVerdict,
        TestPolicyEntry,
        TEST_POLICY_HASH,
        TEST_POLICY_NAME,
        TEST_POLICY_SOURCE,
    };
    use crate::frame::{Frame, Hour, IP, IpVer, Octet, Port, Protocol, Weekday};

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
        let bytes = build_policy_bin(7, TEST_POLICY_SOURCE);

        let file = RgpfFile::parse(&bytes).unwrap();
        let sources = file.policy_sources().unwrap();
        let entries = file.policy_entries().unwrap();

        assert_eq!(file.header().revision_id.get(), 7);
        assert_eq!(entries.entries().len(), 1);
        assert_eq!(sources.get(entries.entries()[0].name_off.get()).unwrap(), TEST_POLICY_NAME);
        assert_eq!(sources.get(entries.entries()[0].source_off.get()).unwrap(), TEST_POLICY_SOURCE);
        assert_eq!(file.default_verdict().unwrap().entry().verdict_kind, VERDICT_DROP);
        assert!(file.nat_rules().unwrap().is_none());
    }

    #[test]
    fn loads_compiled_policy_from_rgpf() {
        let bytes = build_policy_bin(7, TEST_POLICY_SOURCE);

        let file = RgpfFile::parse(&bytes).unwrap();
        let compiled = load_compiled_policy_bundle(&file).unwrap();

        assert_eq!(compiled.metadata().revision_id, Some(7));
        assert_eq!(compiled.metadata().policy_hash, Some(TEST_POLICY_HASH));
        assert_eq!(compiled.metadata().policy_count, 1);
        assert_eq!(compiled.policies().len(), 1);

        let verdict = compiled.evaluate(&DummyFrame::tcp());

        assert_eq!(verdict, Verdict::AllowWarn("allow-from-rgpf".into()));
    }

    #[test]
    fn loads_policies_sorted_by_priority_and_uses_global_default_verdict() {
        let bytes = build_policy_bundle_bin(
            9,
            &[
                TestPolicyEntry {
                    name: "later",
                    priority: 20,
                    dsl_source: "match protocol { = tcp : verdict drop }",
                },
                TestPolicyEntry {
                    name: "earlier",
                    priority: 10,
                    dsl_source: "match protocol { = udp : verdict allow }",
                },
            ],
            TestDefaultVerdict::AllowWarn("global-default"),
        );

        let file = RgpfFile::parse(&bytes).unwrap();
        let compiled = load_compiled_policy_bundle(&file).unwrap();

        assert_eq!(compiled.metadata().policy_count, 2);
        assert_eq!(compiled.policies()[0].name(), "earlier");
        assert_eq!(compiled.policies()[0].priority(), 10);
        assert_eq!(compiled.policies()[1].name(), "later");
        assert_eq!(compiled.policies()[1].priority(), 20);

        let mut frame = DummyFrame::tcp();
        frame.protocol = Protocol::Udp;
        assert_eq!(compiled.evaluate(&frame), Verdict::Allow);

        frame.protocol = Protocol::Icmp;
        assert_eq!(
            compiled.evaluate(&frame),
            Verdict::AllowWarn("global-default".into())
        );
    }

    #[test]
    fn rejects_duplicate_policy_priority() {
        let bytes = build_policy_bundle_bin(
            10,
            &[
                TestPolicyEntry {
                    name: "one",
                    priority: 10,
                    dsl_source: "match protocol { = tcp : verdict allow }",
                },
                TestPolicyEntry {
                    name: "two",
                    priority: 10,
                    dsl_source: "match protocol { = udp : verdict drop }",
                },
            ],
            TestDefaultVerdict::Drop,
        );

        match RgpfFile::parse(&bytes) {
            Ok(_) => panic!("expected duplicate priority validation error"),
            Err(err) => {
                assert!(matches!(
                    err,
                    crate::policy::rgpf::errors::rgpf_error::RgpfError::InvalidLayout(
                        "duplicate policy priority"
                    )
                ));
            }
        }
    }

    #[test]
    fn parses_optional_nat_section() {
        let bytes = build_policy_bin_with_empty_nat(7, TEST_POLICY_SOURCE);

        let file = RgpfFile::parse(&bytes).unwrap();

        assert!(file.nat_rules().unwrap().is_some());
        assert_eq!(file.nat_rules().unwrap().unwrap().rules().len(), 0);
    }

    #[test]
    fn invalid_nat_blocks_rgpf_parse() {
        let bytes = build_policy_bin_with_invalid_nat(7, TEST_POLICY_SOURCE);

        match RgpfFile::parse(&bytes) {
            Ok(_) => panic!("expected invalid nat to fail parse"),
            Err(err) => {
                assert!(matches!(
                    err,
                    crate::policy::rgpf::errors::rgpf_error::RgpfError::InvalidBool(2)
                ));
            }
        }
    }
}
