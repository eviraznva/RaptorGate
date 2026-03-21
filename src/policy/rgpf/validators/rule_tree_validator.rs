use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::rgpf_file::RgpfFile;
use crate::policy::rgpf::sections::rule_tree::sections::{FieldValueSection, PatternSection, RuleTreeSection};

use crate::policy::rgpf::constants::{
    IP_VER_V4,
    IP_VER_V6,
    WEEKDAY_FRI,
    WEEKDAY_MON,
    WEEKDAY_SAT,
    WEEKDAY_SUN,
    WEEKDAY_THU,
    WEEKDAY_TUE,
    WEEKDAY_WED,
    VERDICT_DROP,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    PROTOCOL_ICMP,
    VERDICT_ALLOW,
    FIELD_VALUE_IP,
    MATCH_KIND_HOUR,
    NODE_KIND_MATCH,
    PATTERN_KIND_OR,
    FIELD_VALUE_PORT,
    FIELD_VALUE_HOUR,
    VERDICT_DROP_WARN,
    NODE_KIND_VERDICT,
    PATTERN_KIND_GLOB,
    MATCH_KIND_SRC_IP,
    MATCH_KIND_DST_IP,
    COMPARISON_LESSER,
    MATCH_KIND_IP_VER,
    PATTERN_KIND_EQUAL,
    VERDICT_ALLOW_WARN,
    PATTERN_KIND_RANGE,
    FIELD_VALUE_IP_VER,
    COMPARISON_GREATER,
    MATCH_KIND_SRC_PORT,
    MATCH_KIND_DST_PORT,
    MATCH_KIND_PROTOCOL,
    FIELD_VALUE_PROTOCOL,
    PATTERN_KIND_WILDCARD,
    MATCH_KIND_DAY_OF_WEEK,
    PATTERN_KIND_COMPARISON,
    FIELD_VALUE_DAY_OF_WEEK,
    COMPARISON_LESSER_OR_EQUAL,
    COMPARISON_GREATER_OR_EQUAL,
};

pub fn validate_rule_tree(file: &RgpfFile<'_>, section: &RuleTreeSection<'_>) -> Result<(), RgpfError> {
    let strings = file.string_table()?;

    for rule in section.rules() {
        strings.get(rule.name_str_off.get())?;
        
        if rule.desc_str_off.get() != 0 {
            strings.get(rule.desc_str_off.get())?;
        }
        
        section.node(rule.root_node_index.get())?;
    }

    for node in section.nodes() {
        match node.node_kind {
            NODE_KIND_MATCH => {
                if node.pattern_off.get() == 0 || node.verdict_off.get() != 0 {
                    return Err(RgpfError::InvalidLayout("match node has invalid payload offsets"));
                }

                validate_match_kind(node.match_kind)?;

                if node.yes_index.get() == u32::MAX {
                    return Err(RgpfError::InvalidLayout("match node must have yes_index"));
                }

                section.node(node.yes_index.get())?;
                
                if node.no_index.get() != u32::MAX {
                    section.node(node.no_index.get())?;
                }

                validate_pattern(section, node.match_kind, node.pattern_off.get())?;
            }
            NODE_KIND_VERDICT => {
                if node.pattern_off.get() != 0 || node.verdict_off.get() == 0 {
                    return Err(RgpfError::InvalidLayout("verdict node has invalid payload offsets"));
                }

                validate_verdict(file, section.verdict(node.verdict_off.get())?)?;
            }
            value => {
                return Err(RgpfError::InvalidEnum {
                    field: "rule_node.node_kind",
                    value: u64::from(value),
                });
            }
        }
    }

    validate_verdict(file, file.default_verdict()?.verdict())?;

    Ok(())
}

fn validate_match_kind(value: u8) -> Result<(), RgpfError> {
    if matches!(
        value,
        MATCH_KIND_SRC_IP
            | MATCH_KIND_DST_IP
            | MATCH_KIND_IP_VER
            | MATCH_KIND_DAY_OF_WEEK
            | MATCH_KIND_HOUR
            | MATCH_KIND_PROTOCOL
            | MATCH_KIND_SRC_PORT
            | MATCH_KIND_DST_PORT
    ) {
        return Ok(());
    }

    Err(RgpfError::InvalidEnum {
        field: "rule_node.match_kind",
        value: u64::from(value),
    })
}

fn validate_pattern(section: &RuleTreeSection<'_>, match_kind: u8, offset: u32) -> Result<(), RgpfError> {
    match section.pattern(offset)? {
        PatternSection::Wildcard => Ok(()),
        PatternSection::Equal(value) => validate_field_value(value),
        PatternSection::Glob(value) => {
            if !matches!(match_kind, MATCH_KIND_SRC_IP | MATCH_KIND_DST_IP) {
                return Err(RgpfError::InvalidLayout("glob is only valid for ip matches"));
            }
            match value {
                FieldValueSection::Ip(_) => Ok(()),
                _ => Err(RgpfError::InvalidLayout("glob requires ip field value")),
            }
        }
        PatternSection::Range { lo, hi } => {
            if !matches!(match_kind, MATCH_KIND_SRC_PORT | MATCH_KIND_DST_PORT | MATCH_KIND_HOUR) {
                return Err(RgpfError::InvalidLayout("range is invalid for this match kind"));
            }
            
            validate_field_value(lo)?;
            
            validate_field_value(hi)
        }
        PatternSection::Comparison { op, rhs } => {
            if !matches!(match_kind, MATCH_KIND_SRC_PORT | MATCH_KIND_DST_PORT | MATCH_KIND_HOUR | MATCH_KIND_DAY_OF_WEEK) {
                return Err(RgpfError::InvalidLayout("comparison is invalid for this match kind"));
            }
            
            if !matches!(op, COMPARISON_GREATER | COMPARISON_LESSER | COMPARISON_GREATER_OR_EQUAL | COMPARISON_LESSER_OR_EQUAL) {
                return Err(RgpfError::InvalidEnum {
                    field: "comparison.op",
                    value: u64::from(op),
                });
            }
            
            validate_field_value(rhs)
        }
        PatternSection::Or(or_pattern) => {
            if !matches!(
                match_kind,
                MATCH_KIND_PROTOCOL | MATCH_KIND_DAY_OF_WEEK | MATCH_KIND_IP_VER | MATCH_KIND_HOUR | MATCH_KIND_SRC_IP | MATCH_KIND_DST_IP
            ) {
                return Err(RgpfError::InvalidLayout("or is invalid for this match kind"));
            }

            for nested in or_pattern.pattern_offsets() {
                match section.pattern(nested.get())? {
                    PatternSection::Wildcard
                    | PatternSection::Range { .. }
                    | PatternSection::Comparison { .. }
                    | PatternSection::Or(_) => return Err(RgpfError::InvalidLayout("nested or only supports simple patterns")),
                    PatternSection::Equal(value) | PatternSection::Glob(value) => validate_field_value(value)?,
                }
            }

            Ok(())
        }
    }
}

fn validate_field_value(value: FieldValueSection<'_>) -> Result<(), RgpfError> {
    match value {
        FieldValueSection::Ip(ip) => {
            for mask in [ip.mask0, ip.mask1, ip.mask2, ip.mask3] {
                if !matches!(mask, 0 | 1) {
                    return Err(RgpfError::InvalidBool(mask));
                }
            }
            
            Ok(())
        }
        FieldValueSection::IpVer(value) => {
            if !matches!(value.value, IP_VER_V4 | IP_VER_V6) {
                return Err(RgpfError::InvalidEnum {
                    field: "ip_ver.value",
                    value: u64::from(value.value),
                });
            }
            
            Ok(())
        }
        FieldValueSection::DayOfWeek(value) => {
            if !matches!(value.value, WEEKDAY_MON | WEEKDAY_TUE | WEEKDAY_WED | WEEKDAY_THU | WEEKDAY_FRI | WEEKDAY_SAT | WEEKDAY_SUN) {
                return Err(RgpfError::InvalidEnum {
                    field: "day_of_week.value",
                    value: u64::from(value.value),
                });
            }
            
            Ok(())
        }
        FieldValueSection::Hour(value) => {
            if value.value > 23 {
                return Err(RgpfError::InvalidEnum {
                    field: "hour.value",
                    value: u64::from(value.value),
                });
            }
            
            Ok(())
        }
        FieldValueSection::Protocol(value) => {
            if !matches!(value.value, PROTOCOL_TCP | PROTOCOL_UDP | PROTOCOL_ICMP) {
                return Err(RgpfError::InvalidEnum {
                    field: "protocol.value",
                    value: u64::from(value.value),
                });
            }
            
            Ok(())
        }
        FieldValueSection::Port(_) => Ok(()),
    }
}

fn validate_verdict(file: &RgpfFile<'_>, verdict: &crate::policy::rgpf::sections::rule_tree::entries::VerdictEntry) -> Result<(), RgpfError> {
    if !matches!(verdict.verdict_kind, VERDICT_ALLOW | VERDICT_DROP | VERDICT_ALLOW_WARN | VERDICT_DROP_WARN) {
        return Err(RgpfError::InvalidEnum {
            field: "verdict.kind",
            value: u64::from(verdict.verdict_kind),
        });
    }

    if verdict.message_str_off.get() != 0 {
        file.string_table()?.get(verdict.message_str_off.get())?;
    }

    Ok(())
}
