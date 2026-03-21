use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::rgpf_file::RgpfFile;
use crate::policy::rgpf::sections::nat::sections::NatSection;

use crate::policy::rgpf::constants::{
    NAT_KIND_PAT,
    NAT_KIND_DNAT,
    NAT_KIND_SNAT,
    NAT_PROTO_ANY,
    NAT_PROTO_TCP,
    NAT_PROTO_UDP,
    NAT_PROTO_ICMP,
    NAT_KIND_MASQUERADE,
    NAT_STAGE_PREROUTING,
    NAT_STAGE_POSTROUTING,
};

pub fn validate_nat(file: &RgpfFile<'_>, nat: &NatSection<'_>) -> Result<(), RgpfError> {
    let strings = file.string_table()?;

    for rule in nat.rules() {
        strings.get(rule.id_str_off.get())?;
        
        if rule.name_str_off.get() != 0 {
            strings.get(rule.name_str_off.get())?;
        }

        if !matches!(rule.enabled, 0 | 1) {
            return Err(RgpfError::InvalidBool(rule.enabled));
        }

        if !matches!(rule.applies_at, NAT_STAGE_PREROUTING | NAT_STAGE_POSTROUTING) {
            return Err(RgpfError::InvalidEnum {
                field: "nat_rule.applies_at",
                value: u64::from(rule.applies_at),
            });
        }

        let match_index = usize::try_from(rule.match_index.get()).map_err(|_| RgpfError::OffsetOutOfBounds)?;
        
        let kind_index = usize::try_from(rule.kind_index.get()).map_err(|_| RgpfError::OffsetOutOfBounds)?;
        
        let timeout_index = usize::try_from(rule.timeouts_index.get()).map_err(|_| RgpfError::OffsetOutOfBounds)?;

        let match_entry = nat.matches().get(match_index).ok_or(RgpfError::OffsetOutOfBounds)?;
        
        let kind = nat.kinds().get(kind_index).ok_or(RgpfError::OffsetOutOfBounds)?;
        
        nat.timeouts().get(timeout_index).ok_or(RgpfError::OffsetOutOfBounds)?;

        if !matches!(kind.kind_tag, NAT_KIND_SNAT | NAT_KIND_MASQUERADE | NAT_KIND_DNAT | NAT_KIND_PAT) {
            return Err(RgpfError::InvalidEnum {
                field: "nat_kind.kind_tag",
                value: u64::from(kind.kind_tag),
            });
        }

        let _ = match_entry.presence_bits.get();
    }

    let arena = nat.object_arena();
    
    let mut cursor = 0;
    
    while cursor < arena.len() {
        if arena.len() - cursor < 4 {
            break;
        }
        
        let proto_kind = arena[cursor];
        
        if matches!(proto_kind, NAT_PROTO_ANY | NAT_PROTO_TCP | NAT_PROTO_UDP | NAT_PROTO_ICMP) {
            cursor += 4;
            
            continue;
        }
        
        cursor += 1;
    }

    Ok(())
}
