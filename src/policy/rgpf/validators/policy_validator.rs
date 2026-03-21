use std::collections::BTreeSet;

use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::string_table::StringTable;
use crate::policy::rgpf::sections::policy_table::PolicyEntryTable;
use crate::policy::rgpf::sections::default_verdict::DefaultVerdictSection;

use crate::policy::rgpf::constants::{
    VERDICT_DROP,
    VERDICT_ALLOW,
    VERDICT_DROP_WARN,
    VERDICT_ALLOW_WARN,
};

pub fn validate_policy_entries(
    policy_sources: &StringTable<'_>,
    policy_entries: &PolicyEntryTable<'_>,
) -> Result<(), RgpfError> {
    if policy_entries.entries().is_empty() {
        return Err(RgpfError::InvalidLayout("policy entry table must not be empty"));
    }

    let mut priorities = BTreeSet::new();

    for entry in policy_entries.entries() {
        policy_sources.get(entry.name_off.get())?;
        policy_sources.get(entry.source_off.get())?;

        if !priorities.insert(entry.priority.get()) {
            return Err(RgpfError::InvalidLayout("duplicate policy priority"));
        }
    }

    Ok(())
}

pub fn validate_default_verdict(
    policy_sources: &StringTable<'_>,
    default_verdict: &DefaultVerdictSection<'_>,
) -> Result<(), RgpfError> {
    let entry = default_verdict.entry();

    match entry.verdict_kind {
        VERDICT_ALLOW | VERDICT_DROP => {
            if entry.message_off.get() != 0 {
                return Err(RgpfError::InvalidLayout(
                    "default verdict message is only valid for warn verdicts",
                ));
            }
        }
        VERDICT_ALLOW_WARN | VERDICT_DROP_WARN => {
            if entry.message_off.get() == 0 {
                return Err(RgpfError::InvalidLayout("warn default verdict requires message"));
            }

            policy_sources.get(entry.message_off.get())?;
        }
        value => {
            return Err(RgpfError::InvalidEnum {
                field: "default_verdict.verdict_kind",
                value: u64::from(value),
            });
        }
    }

    Ok(())
}
