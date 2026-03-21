use std::mem::size_of;
use std::collections::BTreeSet;

use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::rgpf_header::RgpfHeader;
use crate::policy::rgpf::sections::rgpf_file::{ensure_magic, ensure_version, RgpfFile};

use crate::policy::rgpf::constants::{
    SECTION_NAT_RULE_TABLE,
    SECTION_DEFAULT_VERDICT,
    SECTION_POLICY_ENTRY_TABLE,
    SECTION_POLICY_SOURCE_TABLE,
};

pub fn validate_header(bytes: &[u8], header: &RgpfHeader) -> Result<(), RgpfError> {
    ensure_magic(header.magic.get())?;

    ensure_version(header.major.get(), header.minor.get())?;

    let header_len = usize::from(header.header_len.get());

    if header_len != size_of::<RgpfHeader>() {
        return Err(RgpfError::InvalidHeaderLength(header.header_len.get()));
    }

    let declared_len = usize::try_from(header.file_len.get()).map_err(|_| RgpfError::OffsetOutOfBounds)?;

    if declared_len != bytes.len() {
        return Err(RgpfError::InvalidFileLength {
            declared: header.file_len.get(),
            actual: bytes.len(),
        });
    }

    let expected_crc = header.file_crc32c.get();

    let actual_crc = crc32c_with_zeroed_field(bytes, file_crc32c_offset());

    if expected_crc != actual_crc {
        return Err(RgpfError::InvalidCrc32c);
    }

    Ok(())
}

pub fn validate_sections(file: &RgpfFile<'_>) -> Result<(), RgpfError> {
    let mut kinds = BTreeSet::new();

    for section in file.sections() {
        let kind = section.kind.get();

        if !kinds.insert(kind) {
            return Err(RgpfError::DuplicateSection(kind));
        }

        let offset = usize::try_from(section.offset.get()).map_err(|_| RgpfError::OffsetOutOfBounds)?;

        let length = usize::try_from(section.length.get()).map_err(|_| RgpfError::OffsetOutOfBounds)?;

        let end = offset.checked_add(length).ok_or(RgpfError::IntegerOverflow)?;

        if end > file.bytes().len() {
            return Err(RgpfError::SectionOutOfBounds);
        }
    }

    if !kinds.contains(&SECTION_POLICY_ENTRY_TABLE) {
        return Err(RgpfError::MissingSection("POLICY_ENTRY_TABLE"));
    }

    if !kinds.contains(&SECTION_POLICY_SOURCE_TABLE) {
        return Err(RgpfError::MissingSection("POLICY_SOURCE_TABLE"));
    }

    if !kinds.contains(&SECTION_DEFAULT_VERDICT) {
        return Err(RgpfError::MissingSection("DEFAULT_VERDICT"));
    }

    for kind in kinds {
        if !matches!(
            kind,
            SECTION_DEFAULT_VERDICT
                | SECTION_NAT_RULE_TABLE
                | SECTION_POLICY_ENTRY_TABLE
                | SECTION_POLICY_SOURCE_TABLE
        ) {
            return Err(RgpfError::InvalidSection("unknown section kind"));
        }
    }

    Ok(())
}

fn file_crc32c_offset() -> usize { 56 }

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
