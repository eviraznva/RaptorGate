use std::mem::size_of;
use zerocopy::FromBytes;

use crate::policy::rgpf::validators::nat_validator;
use crate::policy::rgpf::validators::policy_validator;
use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::validators::rgpf_file_validator;
use crate::policy::rgpf::sections::rgpf_header::RgpfHeader;
use crate::policy::rgpf::sections::string_table::StringTable;
use crate::policy::rgpf::sections::nat::sections::NatSection;
use crate::policy::rgpf::sections::policy_table::PolicyEntryTable;
use crate::policy::rgpf::sections::default_verdict::DefaultVerdictSection;
use crate::policy::rgpf::sections::section_table::{SectionEntry, SectionTable};

use crate::policy::rgpf::constants::{
    RGPF_MAGIC,
    RGPF_MAJOR,
    RGPF_MINOR,
    SECTION_NAT_RULE_TABLE,
    SECTION_DEFAULT_VERDICT,
    SECTION_POLICY_ENTRY_TABLE,
    SECTION_POLICY_SOURCE_TABLE,
};

pub struct RgpfFile<'a> {
    bytes: &'a [u8],
    header: &'a RgpfHeader,
    sections: &'a [SectionEntry],
}

impl<'a> RgpfFile<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, RgpfError> {
        let header = RgpfHeader::ref_from_prefix(bytes)
            .map_err(|_| RgpfError::InvalidLayout("file is shorter than header"))?.0;

        rgpf_file_validator::validate_header(bytes, header)?;

        let table_offset = usize::try_from(header.section_table_offset.get())
            .map_err(|_| RgpfError::OffsetOutOfBounds)?;

        let section_count = usize::from(header.section_count.get());

        let table_len = size_of::<SectionEntry>().checked_mul(section_count)
            .ok_or(RgpfError::IntegerOverflow)?;

        let table_end = table_offset.checked_add(table_len).ok_or(RgpfError::IntegerOverflow)?;

        let table_bytes = bytes.get(table_offset..table_end).ok_or(RgpfError::SectionOutOfBounds)?;

        let sections = <[SectionEntry]>::ref_from_bytes_with_elems(table_bytes, section_count)
            .map_err(|_| RgpfError::InvalidLayout("invalid section table layout"))?;

        let file = Self { bytes, header, sections };

        rgpf_file_validator::validate_sections(&file)?;

        let policy_sources = file.policy_sources()?;
        let policy_entries = file.policy_entries()?;
        let default_verdict = file.default_verdict()?;

        policy_validator::validate_policy_entries(&policy_sources, &policy_entries)?;
        policy_validator::validate_default_verdict(&policy_sources, &default_verdict)?;

        if let Some(nat_rules) = file.nat_rules()? {
            nat_validator::validate_nat(&file, &nat_rules)?;
        }

        Ok(file)
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn header(&self) -> &'a RgpfHeader {
        self.header
    }

    pub fn sections(&self) -> &'a [SectionEntry] {
        self.sections
    }

    pub fn section(&self, kind: u16) -> Result<Option<SectionTable<'a>>, RgpfError> {
        let mut found = None;

        for entry in self.sections {
            if entry.kind.get() != kind {
                continue;
            }

            if found.is_some() {
                return Err(RgpfError::DuplicateSection(kind));
            }

            let offset = usize::try_from(entry.offset.get()).map_err(|_| RgpfError::OffsetOutOfBounds)?;

            let len = usize::try_from(entry.length.get()).map_err(|_| RgpfError::OffsetOutOfBounds)?;

            let end = offset.checked_add(len).ok_or(RgpfError::IntegerOverflow)?;

            let bytes = self.bytes.get(offset..end).ok_or(RgpfError::SectionOutOfBounds)?;

            found = Some(SectionTable { entry, bytes });
        }

        Ok(found)
    }

    pub fn policy_entries(&self) -> Result<PolicyEntryTable<'a>, RgpfError> {
        let section = self.section(SECTION_POLICY_ENTRY_TABLE)?
            .ok_or(RgpfError::MissingSection("POLICY_ENTRY_TABLE"))?;

        PolicyEntryTable::parse(section)
    }

    pub fn policy_sources(&self) -> Result<StringTable<'a>, RgpfError> {
        let section = self.section(SECTION_POLICY_SOURCE_TABLE)?
            .ok_or(RgpfError::MissingSection("POLICY_SOURCE_TABLE"))?;

        Ok(StringTable::new(section.bytes))
    }

    pub fn string_table(&self) -> Result<StringTable<'a>, RgpfError> {
        self.policy_sources()
    }

    pub fn default_verdict(&self) -> Result<DefaultVerdictSection<'a>, RgpfError> {
        let section = self.section(SECTION_DEFAULT_VERDICT)?
            .ok_or(RgpfError::MissingSection("DEFAULT_VERDICT"))?;

        DefaultVerdictSection::parse(section)
    }

    pub fn nat_rules(&self) -> Result<Option<NatSection<'a>>, RgpfError> {
        match self.section(SECTION_NAT_RULE_TABLE)? {
            Some(section) => Ok(Some(NatSection::parse(section)?)),
            None => Ok(None),
        }
    }
}

pub(crate) fn ensure_version(major: u16, minor: u16) -> Result<(), RgpfError> {
    if major != RGPF_MAJOR || minor != RGPF_MINOR {
        return Err(RgpfError::UnsupportedVersion { major, minor });
    }

    Ok(())
}

pub(crate) fn ensure_magic(magic: u32) -> Result<(), RgpfError> {
    if magic != RGPF_MAGIC {
        return Err(RgpfError::InvalidMagic(magic));
    }

    Ok(())
}
