use std::collections::HashMap;

use anyhow::{anyhow, Result};

use crate::control_plane::proto_types::raptorgate::config::{
    IdentityUser, IpsSignature, MlModel, NatRule, Rule, SslBypassEntry,
    UserGroup, UserGroupMember, Zone, ZoneInterface, ZonePair, ConfigBundle,
    ConfigSnapshotResponse, DnsBlacklistEntry, FirewallCertificate, IdentityManagerUserSession,
};

use crate::control_plane::runtime_firewall_rules::{
    RuntimeFirewallRules, RuntimeFirewallRulesIndexes, RuntimeFirewallRulesMeta,
    RuntimeIdentitySession, RuntimeIdentityUser, RuntimeIpsSignature, RuntimeMlModel,
    RuntimeZoneInterface, RuntimeZonePair, RuntimeDnsBlacklistEntry, RuntimeFirewallCertificate,
    RuntimeNatRule, RuntimeRule, RuntimeSslBypassEntry, RuntimeUserGroup, RuntimeUserGroupMember, RuntimeZone,
};

pub fn map_config_snapshot_response_to_runtime_rules(
    snapshot: &ConfigSnapshotResponse,
) -> Result<RuntimeFirewallRules> {
    let bundle = snapshot
        .active_configuration
        .as_ref()
        .ok_or_else(|| anyhow!("ConfigSnapshotResponse.active_configuration is missing"))?;

    Ok(map_config_bundle_to_runtime_rules(
        bundle,
        snapshot.config_version,
        snapshot.bundle_checksum.clone(),
    ))
}

pub fn map_config_bundle_to_runtime_rules(
    bundle: &ConfigBundle,
    config_version: u64,
    bundle_checksum: String,
) -> RuntimeFirewallRules {
    let rules: Vec<RuntimeRule> = bundle
        .rules
        .as_ref()
        .map(|set| set.items.iter().map(map_rule).collect::<Vec<_>>())
        .unwrap_or_default();

    let zones: Vec<RuntimeZone> = bundle
        .zones
        .as_ref()
        .map(|set| set.items.iter().map(map_zone).collect::<Vec<_>>())
        .unwrap_or_default();

    let zone_interfaces: Vec<RuntimeZoneInterface> = bundle
        .zone_interfaces
        .as_ref()
        .map(|set| set.items.iter().map(map_zone_interface).collect::<Vec<_>>())
        .unwrap_or_default();

    let zone_pairs: Vec<RuntimeZonePair> = bundle
        .zone_pairs
        .as_ref()
        .map(|set| set.items.iter().map(map_zone_pair).collect::<Vec<_>>())
        .unwrap_or_default();

    let nat_rules: Vec<RuntimeNatRule> = bundle
        .nat_rules
        .as_ref()
        .map(|set| set.items.iter().map(map_nat_rule).collect::<Vec<_>>())
        .unwrap_or_default();

    let dns_blacklist: Vec<RuntimeDnsBlacklistEntry> = bundle
        .dns_blacklist
        .as_ref()
        .map(|set| {
            set.items
                .iter()
                .map(map_dns_blacklist_entry)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let ssl_bypass_list: Vec<RuntimeSslBypassEntry> = bundle
        .ssl_bypass_list
        .as_ref()
        .map(|set| {
            set.items
                .iter()
                .map(map_ssl_bypass_entry)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let ips_signatures: Vec<RuntimeIpsSignature> = bundle
        .ips_signatures
        .as_ref()
        .map(|set| set.items.iter().map(map_ips_signature).collect::<Vec<_>>())
        .unwrap_or_default();

    let ml_model = bundle.ml_model.as_ref().map(map_ml_model);

    let firewall_certificates: Vec<RuntimeFirewallCertificate> = bundle
        .firewall_certificates
        .as_ref()
        .map(|set| {
            set.items
                .iter()
                .map(map_firewall_certificate)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let identity_user_groups: Vec<RuntimeUserGroup> = bundle
        .identity
        .as_ref()
        .map(|identity| {
            identity
                .user_groups
                .iter()
                .map(map_user_group)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let identity_users: Vec<RuntimeIdentityUser> = bundle
        .identity
        .as_ref()
        .map(|identity| {
            identity
                .identity_users
                .iter()
                .map(map_identity_user)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let identity_group_members: Vec<RuntimeUserGroupMember> = bundle
        .identity
        .as_ref()
        .map(|identity| {
            identity
                .user_group_members
                .iter()
                .map(map_user_group_member)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let identity_sessions: Vec<RuntimeIdentitySession> = bundle
        .identity
        .as_ref()
        .map(|identity| {
            identity
                .identity_manager_user_sessions
                .iter()
                .map(map_identity_session)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let indexes = build_indexes(
        &rules,
        &zones,
        &zone_interfaces,
        &zone_pairs,
        &nat_rules,
        &dns_blacklist,
        &ssl_bypass_list,
        &ips_signatures,
        &identity_user_groups,
        &identity_users,
        &identity_group_members,
        &identity_sessions,
    );

    RuntimeFirewallRules {
        meta: RuntimeFirewallRulesMeta {
            config_version,
            bundle_checksum,
        },
        rules,
        zones,
        zone_interfaces,
        zone_pairs,
        nat_rules,
        dns_blacklist,
        ssl_bypass_list,
        ips_signatures,
        ml_model,
        firewall_certificates,
        identity_user_groups,
        identity_users,
        identity_group_members,
        identity_sessions,
        indexes,
    }
}

fn build_indexes(
    rules: &[RuntimeRule],
    zones: &[RuntimeZone],
    zone_interfaces: &[RuntimeZoneInterface],
    zone_pairs: &[RuntimeZonePair],
    nat_rules: &[RuntimeNatRule],
    dns_blacklist: &[RuntimeDnsBlacklistEntry],
    ssl_bypass_list: &[RuntimeSslBypassEntry],
    ips_signatures: &[RuntimeIpsSignature],
    user_groups: &[RuntimeUserGroup],
    identity_users: &[RuntimeIdentityUser],
    group_members: &[RuntimeUserGroupMember],
    sessions: &[RuntimeIdentitySession],
) -> RuntimeFirewallRulesIndexes {
    let mut user_groups_by_user_id: HashMap<String, Vec<String>> = HashMap::new();

    for membership in group_members {
        user_groups_by_user_id
            .entry(membership.identity_user_id.clone())
            .or_default()
            .push(membership.group_id.clone());
    }

    RuntimeFirewallRulesIndexes {
        zones_by_id: zones
            .iter()
            .cloned()
            .map(|zone| (zone.id.clone(), zone))
            .collect(),
        zone_pairs_by_id: zone_pairs
            .iter()
            .cloned()
            .map(|pair| (pair.id.clone(), pair))
            .collect(),
        zone_interfaces_by_name: zone_interfaces
            .iter()
            .cloned()
            .map(|iface| (iface.interface_name.clone(), iface))
            .collect(),
        rules_by_id: rules
            .iter()
            .cloned()
            .map(|rule| (rule.id.clone(), rule))
            .collect(),
        nat_rules_by_id: nat_rules
            .iter()
            .cloned()
            .map(|rule| (rule.id.clone(), rule))
            .collect(),
        dns_blacklist_by_domain: dns_blacklist
            .iter()
            .cloned()
            .map(|entry| (entry.domain.clone(), entry))
            .collect(),
        ssl_bypass_by_domain: ssl_bypass_list
            .iter()
            .cloned()
            .map(|entry| (entry.domain.clone(), entry))
            .collect(),
        ips_signatures_by_id: ips_signatures
            .iter()
            .cloned()
            .map(|signature| (signature.id.clone(), signature))
            .collect(),
        identity_users_by_id: identity_users
            .iter()
            .cloned()
            .map(|user| (user.id.clone(), user))
            .collect(),
        user_groups_by_id: user_groups
            .iter()
            .cloned()
            .map(|group| (group.id.clone(), group))
            .collect(),
        sessions_by_ip: sessions
            .iter()
            .cloned()
            .map(|session| (session.ip_address.clone(), session))
            .collect(),
        user_groups_by_user_id,
    }
}

fn map_rule(rule: &Rule) -> RuntimeRule {
    RuntimeRule {
        id: rule.id.clone(),
        name: rule.name.clone(),
        zone_pair_id: rule.zone_pair_id.clone(),
        priority: rule.priority,
        content: rule.content.clone(),
    }
}

fn map_zone(zone: &Zone) -> RuntimeZone {
    RuntimeZone {
        id: zone.id.clone(),
        name: zone.name.clone(),
    }
}

fn map_zone_interface(interface: &ZoneInterface) -> RuntimeZoneInterface {
    RuntimeZoneInterface {
        id: interface.id.clone(),
        zone_id: interface.zone_id.clone(),
        interface_name: interface.interface_name.clone(),
        vlan_id: interface.vlan_id,
    }
}

fn map_zone_pair(zone_pair: &ZonePair) -> RuntimeZonePair {
    RuntimeZonePair {
        id: zone_pair.id.clone(),
        src_zone_id: zone_pair.src_zone_id.clone(),
        dst_zone_id: zone_pair.dst_zone_id.clone(),
        default_policy: zone_pair.default_policy,
    }
}

fn map_nat_rule(rule: &NatRule) -> RuntimeNatRule {
    RuntimeNatRule {
        id: rule.id.clone(),
        nat_type: rule.r#type,
        src_ip: rule.src_ip.clone(),
        dst_ip: rule.dst_ip.clone(),
        src_port: rule.src_port,
        dst_port: rule.dst_port,
        translated_ip: rule.translated_ip.clone(),
        translated_port: rule.translated_port,
        priority: rule.priority,
    }
}

fn map_dns_blacklist_entry(entry: &DnsBlacklistEntry) -> RuntimeDnsBlacklistEntry {
    RuntimeDnsBlacklistEntry {
        id: entry.id.clone(),
        domain: entry.domain.clone(),
    }
}

fn map_ssl_bypass_entry(entry: &SslBypassEntry) -> RuntimeSslBypassEntry {
    RuntimeSslBypassEntry {
        id: entry.id.clone(),
        domain: entry.domain.clone(),
    }
}

fn map_ips_signature(signature: &IpsSignature) -> RuntimeIpsSignature {
    RuntimeIpsSignature {
        id: signature.id.clone(),
        name: signature.name.clone(),
        category: signature.category.clone(),
        pattern: signature.pattern.clone(),
        severity: signature.severity,
    }
}

fn map_ml_model(model: &MlModel) -> RuntimeMlModel {
    RuntimeMlModel {
        id: model.id.clone(),
        name: model.name.clone(),
        artifact_path: model.artifact_path.clone(),
        checksum: model.checksum.clone(),
    }
}

fn map_firewall_certificate(certificate: &FirewallCertificate) -> RuntimeFirewallCertificate {
    RuntimeFirewallCertificate {
        id: certificate.id.clone(),
        cert_type: certificate.cert_type,
        common_name: certificate.common_name.clone(),
        fingerprint: certificate.fingerprint.clone(),
        certificate_pem: certificate.certificate_pem.clone(),
        private_key_ref: certificate.private_key_ref.clone(),
        expires_at_unix: certificate.expires_at.as_ref().map(|ts| ts.seconds),
    }
}

fn map_user_group(group: &UserGroup) -> RuntimeUserGroup {
    RuntimeUserGroup {
        id: group.id.clone(),
        name: group.name.clone(),
        source: group.source,
    }
}

fn map_identity_user(user: &IdentityUser) -> RuntimeIdentityUser {
    RuntimeIdentityUser {
        id: user.id.clone(),
        username: user.username.clone(),
        display_name: user.display_name.clone(),
        source: user.source,
        external_id: user.external_id.clone(),
    }
}

fn map_user_group_member(member: &UserGroupMember) -> RuntimeUserGroupMember {
    RuntimeUserGroupMember {
        id: member.id.clone(),
        group_id: member.group_id.clone(),
        identity_user_id: member.identity_user_id.clone(),
    }
}

fn map_identity_session(session: &IdentityManagerUserSession) -> RuntimeIdentitySession {
    RuntimeIdentitySession {
        id: session.id.clone(),
        identity_user_id: session.identity_user_id.clone(),
        radius_username: session.radius_username.clone(),
        mac_address: session.mac_address.clone(),
        ip_address: session.ip_address.clone(),
        nas_ip: session.nas_ip.clone(),
        called_station_id: session.called_station_id.clone(),
        authenticated_at_unix: session.authenticated_at.as_ref().map(|ts| ts.seconds),
        expires_at_unix: session.expires_at.as_ref().map(|ts| ts.seconds),
    }
}
