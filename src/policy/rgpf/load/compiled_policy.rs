use crate::frame::{Hour, IP, IpVer, Octet, Port, Protocol, Weekday};

use crate::policy_evaluator::PolicyEvaluator;
use crate::policy::rgpf::errors::rgpf_error::RgpfError;
use crate::policy::rgpf::sections::rgpf_file::RgpfFile;
use crate::policy::runtime::{CompiledPolicy, PolicyMetadata, PolicySource};
use crate::rule_tree::{ArmEnd, FieldValue, MatchBuilder, MatchKind, Operation, Pattern, RuleTree, Verdict};
use crate::policy::rgpf::sections::rule_tree::sections::{FieldValueSection, PatternSection, RuleTreeSection};

use crate::policy::rgpf::constants::{
    NO_INDEX,
    IP_VER_V4,
    IP_VER_V6,
    WEEKDAY_FRI,
    WEEKDAY_MON,
    WEEKDAY_SAT,
    WEEKDAY_SUN,
    WEEKDAY_THU,
    WEEKDAY_TUE,
    WEEKDAY_WED,
    PROTOCOL_UDP,
    PROTOCOL_TCP,
    VERDICT_DROP,
    PROTOCOL_ICMP,
    VERDICT_ALLOW,
    MATCH_KIND_HOUR,
    NODE_KIND_MATCH,
    NODE_KIND_VERDICT,
    MATCH_KIND_SRC_IP,
    MATCH_KIND_DST_IP,
    COMPARISON_LESSER,
    VERDICT_DROP_WARN,
    MATCH_KIND_IP_VER,
    VERDICT_ALLOW_WARN,
    COMPARISON_GREATER,
    MATCH_KIND_PROTOCOL,
    MATCH_KIND_DST_PORT,
    MATCH_KIND_SRC_PORT,
    MATCH_KIND_DAY_OF_WEEK,
    COMPARISON_LESSER_OR_EQUAL,
    COMPARISON_GREATER_OR_EQUAL,
};

pub fn load_compiled_policy(file: &RgpfFile<'_>) -> Result<CompiledPolicy, RgpfError> {
    let strings = file.string_table()?;
    
    let rule_tree = file.rule_tree()?;
    
    let default_verdict = file.default_verdict()?;

    if rule_tree.rules().len() != 1 {
        return Err(RgpfError::UnsupportedLayout("current runtime supports exactly one filter rule"));
    }

    let rule = &rule_tree.rules()[0];
    
    let name = strings.get(rule.name_str_off.get())?.to_owned();
    
    let description = if rule.desc_str_off.get() == 0 {
        String::new()
    } else {
        strings.get(rule.desc_str_off.get())?.to_owned()
    };
    
    let head = build_match(file, &rule_tree, rule.root_node_index.get(), &mut Vec::new())?;
    
    let default_verdict = build_verdict(file, default_verdict.verdict())?;

    Ok(CompiledPolicy::new(
        PolicyMetadata {
            config_version: Some(file.header().revision_id.get()),
            bundle_checksum: Some(format!("{:016x}", file.header().policy_hash.get())),
            source: PolicySource::Snapshot,
            rule_count: rule_tree.rules().len(),
        },
        PolicyEvaluator::new(RuleTree::new(name, description, head), default_verdict),
    ))
}

fn build_match(file: &RgpfFile<'_>, section: &RuleTreeSection<'_>, root_index: u32, stack: &mut Vec<u32>) -> Result<crate::rule_tree::matcher::Match, RgpfError> {
    if stack.contains(&root_index) {
        return Err(RgpfError::InvalidLayout("cycle detected in rule graph"));
    }

    stack.push(root_index);

    let root = section.node(root_index)?;
    
    if root.node_kind != NODE_KIND_MATCH {
        stack.pop();
        return Err(RgpfError::InvalidLayout("rule root must point to match node"));
    }

    let kind = build_match_kind(root.match_kind)?;
    
    let mut current_index = root_index;
    
    let mut builder: Option<MatchBuilder> = None;

    loop {
        let node = section.node(current_index)?;
        
        if node.node_kind != NODE_KIND_MATCH {
            stack.pop();
            return Err(RgpfError::InvalidLayout("arm chain contains non-match node"));
        }
        
        if node.match_kind != root.match_kind {
            stack.pop();
            return Err(RgpfError::UnsupportedLayout("no_index chain changed match kind"));
        }

        let pattern = build_pattern(section, node.pattern_off.get())?;
        
        let arm_end = build_arm_end(file, section, node.yes_index.get(), stack)?;
        
        builder = Some(match builder {
            Some(existing) => existing.arm(pattern, arm_end),
            None => MatchBuilder::with_arm(kind, pattern, arm_end),
        });

        if node.no_index.get() == NO_INDEX {
            break;
        }

        current_index = node.no_index.get();
    }

    stack.pop();
    
    builder.expect("at least one arm").build().map_err(|_| RgpfError::InvalidLayout("failed to build runtime match"))
}

fn build_arm_end(file: &RgpfFile<'_>, section: &RuleTreeSection<'_>, next_index: u32, stack: &mut Vec<u32>) -> Result<ArmEnd, RgpfError> {
    if next_index == NO_INDEX {
        return Err(RgpfError::InvalidLayout("yes edge must not be terminal"));
    }

    let node = section.node(next_index)?;
    
    match node.node_kind {
        NODE_KIND_MATCH => Ok(ArmEnd::Match(build_match(file, section, next_index, stack)?)),
        NODE_KIND_VERDICT => Ok(ArmEnd::Verdict(build_verdict_from_section(file, section, node.verdict_off.get())?)),
        _ => Err(RgpfError::InvalidLayout("invalid arm target node kind")),
    }
}

fn build_pattern(section: &RuleTreeSection<'_>, offset: u32) -> Result<Pattern, RgpfError> {
    match section.pattern(offset)? {
        PatternSection::Wildcard => Ok(Pattern::Wildcard),
        PatternSection::Equal(value) => Ok(Pattern::Equal(build_field_value(value)?)),
        PatternSection::Glob(value) => Ok(Pattern::Glob(build_field_value(value)?)),
        PatternSection::Range { lo, hi } => Ok(Pattern::Range(build_field_value(lo)?, build_field_value(hi)?)),
        PatternSection::Comparison { op, rhs } => Ok(Pattern::Comparison(build_operation(op)?, build_field_value(rhs)?)),
        PatternSection::Or(or_pattern) => {
            let mut patterns = Vec::new();
            
            for nested_offset in or_pattern.pattern_offsets() {
                patterns.push(build_pattern(section, nested_offset.get())?);
            }
            
            Ok(Pattern::Or(patterns))
        }
    }
}

fn build_field_value(value: FieldValueSection<'_>) -> Result<FieldValue, RgpfError> {
    match value {
        FieldValueSection::Ip(ip) => Ok(FieldValue::Ip(IP::new([
            octet(ip.octet0, ip.mask0)?,
            octet(ip.octet1, ip.mask1)?,
            octet(ip.octet2, ip.mask2)?,
            octet(ip.octet3, ip.mask3)?,
        ]))),
        FieldValueSection::IpVer(value) => Ok(FieldValue::IpVer(build_ip_ver(value.value)?)),
        FieldValueSection::DayOfWeek(value) => Ok(FieldValue::DayOfWeek(build_weekday(value.value)?)),
        FieldValueSection::Hour(value) => Ok(FieldValue::Hour(Hour::try_from(value.value).map_err(|_| RgpfError::InvalidEnum {
            field: "hour.value",
            value: u64::from(value.value),
        })?)),
        FieldValueSection::Protocol(value) => Ok(FieldValue::Protocol(build_protocol(value.value)?)),
        FieldValueSection::Port(value) => Ok(FieldValue::Port(Port::from(value.value.get()))),
    }
}

fn build_match_kind(kind: u8) -> Result<MatchKind, RgpfError> {
    match kind {
        MATCH_KIND_SRC_IP => Ok(MatchKind::SrcIp),
        MATCH_KIND_DST_IP => Ok(MatchKind::DstIp),
        MATCH_KIND_IP_VER => Ok(MatchKind::IpVer),
        MATCH_KIND_DAY_OF_WEEK => Ok(MatchKind::DayOfWeek),
        MATCH_KIND_HOUR => Ok(MatchKind::Hour),
        MATCH_KIND_PROTOCOL => Ok(MatchKind::Protocol),
        MATCH_KIND_SRC_PORT => Ok(MatchKind::SrcPort),
        MATCH_KIND_DST_PORT => Ok(MatchKind::DstPort),
        value => Err(RgpfError::InvalidEnum {
            field: "rule_node.match_kind",
            value: u64::from(value),
        }),
    }
}

fn build_operation(op: u8) -> Result<Operation, RgpfError> {
    match op {
        COMPARISON_GREATER => Ok(Operation::Greater),
        COMPARISON_LESSER => Ok(Operation::Lesser),
        COMPARISON_GREATER_OR_EQUAL => Ok(Operation::GreaterOrEqual),
        COMPARISON_LESSER_OR_EQUAL => Ok(Operation::LesserOrEqual),
        value => Err(RgpfError::InvalidEnum {
            field: "comparison.op",
            value: u64::from(value),
        }),
    }
}

fn build_ip_ver(value: u8) -> Result<IpVer, RgpfError> {
    match value {
        IP_VER_V4 => Ok(IpVer::V4),
        IP_VER_V6 => Ok(IpVer::V6),
        other => Err(RgpfError::InvalidEnum {
            field: "ip_ver.value",
            value: u64::from(other),
        }),
    }
}

fn build_protocol(value: u8) -> Result<Protocol, RgpfError> {
    match value {
        PROTOCOL_TCP => Ok(Protocol::Tcp),
        PROTOCOL_UDP => Ok(Protocol::Udp),
        PROTOCOL_ICMP => Ok(Protocol::Icmp),
        other => Err(RgpfError::InvalidEnum {
            field: "protocol.value",
            value: u64::from(other),
        }),
    }
}

fn build_weekday(value: u8) -> Result<Weekday, RgpfError> {
    match value {
        WEEKDAY_MON => Ok(Weekday::Mon),
        WEEKDAY_TUE => Ok(Weekday::Tue),
        WEEKDAY_WED => Ok(Weekday::Wed),
        WEEKDAY_THU => Ok(Weekday::Thu),
        WEEKDAY_FRI => Ok(Weekday::Fri),
        WEEKDAY_SAT => Ok(Weekday::Sat),
        WEEKDAY_SUN => Ok(Weekday::Sun),
        other => Err(RgpfError::InvalidEnum {
            field: "day_of_week.value",
            value: u64::from(other),
        }),
    }
}

fn build_verdict(file: &RgpfFile<'_>, verdict: &crate::policy::rgpf::sections::rule_tree::entries::VerdictEntry) -> Result<Verdict, RgpfError> {
    let message = if verdict.message_str_off.get() == 0 {
        None
    } else {
        Some(file.string_table()?.get(verdict.message_str_off.get())?.to_owned())
    };

    match verdict.verdict_kind {
        VERDICT_ALLOW => Ok(Verdict::Allow),
        VERDICT_DROP => Ok(Verdict::Drop),
        VERDICT_ALLOW_WARN => Ok(Verdict::AllowWarn(message.unwrap_or_default())),
        VERDICT_DROP_WARN => Ok(Verdict::DropWarn(message.unwrap_or_default())),
        value => Err(RgpfError::InvalidEnum {
            field: "verdict.kind",
            value: u64::from(value),
        }),
    }
}

fn build_verdict_from_section(file: &RgpfFile<'_>, section: &RuleTreeSection<'_>, offset: u32) -> Result<Verdict, RgpfError> {
    build_verdict(file, section.verdict(offset)?)
}

fn octet(value: u8, mask: u8) -> Result<Octet, RgpfError> {
    match mask {
        0 => Ok(Octet::Value(value)),
        1 => Ok(Octet::Any),
        other => Err(RgpfError::InvalidBool(other)),
    }
}
