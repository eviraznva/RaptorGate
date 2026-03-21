use crate::policy::compiler;
use crate::rule_tree::Verdict;
use crate::policy::runtime::CompiledPolicyBundle;
use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::rgpf_file::RgpfFile;

use crate::policy::rgpf::constants::{
    VERDICT_DROP,
    VERDICT_ALLOW,
    VERDICT_DROP_WARN,
    VERDICT_ALLOW_WARN,
};


/// Buduje `CompiledPolicyBundle` przez kompilację wszystkich polityk DSL zapisanych w `RGPF/1`.
pub fn load_compiled_policy_bundle(file: &RgpfFile<'_>) -> Result<CompiledPolicyBundle, RgpfError> {
    let policy_sources = file.policy_sources()?;
    
    let policy_entries = file.policy_entries()?;
    
    let default_verdict = decode_default_verdict(file)?;

    let mut policies = Vec::with_capacity(policy_entries.entries().len());

    for entry in policy_entries.entries() {
        let name = policy_sources.get(entry.name_off.get())?;
        
        let source = policy_sources.get(entry.source_off.get())?;

        let policy = compiler::compile_policy_entry(name, entry.priority.get(), source)
            .map_err(|err| RgpfError::PolicyCompileFailed(err.to_string()))?;

        policies.push(policy);
    }

    Ok(compiler::build_runtime_store_bundle(
        file.header().revision_id.get(),
        file.header().policy_hash.get(),
        policies,
        default_verdict,
    ))
}

fn decode_default_verdict(file: &RgpfFile<'_>) -> Result<Verdict, RgpfError> {
    let sources = file.policy_sources()?;
    
    let entry = file.default_verdict()?.entry();

    match entry.verdict_kind {
        VERDICT_ALLOW => Ok(Verdict::Allow),
        VERDICT_DROP => Ok(Verdict::Drop),
        VERDICT_ALLOW_WARN => Ok(Verdict::AllowWarn(
            sources.get(entry.message_off.get())?.to_owned(),
        )),
        VERDICT_DROP_WARN => Ok(Verdict::DropWarn(
            sources.get(entry.message_off.get())?.to_owned(),
        )),
        value => Err(RgpfError::InvalidEnum {
            field: "default_verdict.verdict_kind",
            value: u64::from(value),
        }),
    }
}
