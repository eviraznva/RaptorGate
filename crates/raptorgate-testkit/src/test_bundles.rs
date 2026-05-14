use ngfw::proto::common::DefaultPolicy;
use ngfw::proto::config::{Rule, SmtpMatchers, Zone, ZonePair};
use ngfw::proto::services::ConfigBundle;
use uuid::Uuid;

use crate::config_bundle::{physical_zone_interface, ConfigBundleBuilder};

pub fn dual_zone_allow_ipv4_bundle() -> ConfigBundle {
    let z1 = Uuid::now_v7();
    let z2 = Uuid::now_v7();
    let zp = Uuid::now_v7();
    let zq = Uuid::now_v7();
    let zi1 = Uuid::now_v7();
    let zi2 = Uuid::now_v7();

    let zones = vec![
        Zone {
            id: Uuid::nil().to_string(),
            name: "default".to_string(),
        },
        Zone {
            id: z1.to_string(),
            name: "zone1".to_string(),
        },
        Zone {
            id: z2.to_string(),
            name: "zone2".to_string(),
        },
    ];

    let zone_interfaces = vec![
        physical_zone_interface(zi1, &z1.to_string(), "eth1", true),
        physical_zone_interface(zi2, &z2.to_string(), "eth2", true),
    ];

    let zone_pairs = vec![
        ZonePair {
            id: zp.to_string(),
            src_zone_id: z1.to_string(),
            dst_zone_id: z2.to_string(),
            default_policy: DefaultPolicy::Unspecified as i32,
        },
        ZonePair {
            id: zq.to_string(),
            src_zone_id: z2.to_string(),
            dst_zone_id: z1.to_string(),
            default_policy: DefaultPolicy::Unspecified as i32,
        },
    ];

    let allow_v4 = r#"
            match ip_ver {
              =v4: verdict allow
              =v6: verdict drop
            }
          "#;

    let rules = vec![
        Rule {
            id: Uuid::now_v7().to_string(),
            name: "zone1-to-zone2".to_string(),
            zone_pair_id: zp.to_string(),
            priority: 0,
            content: allow_v4.to_string(),
            smtp_matchers: None,
        },
        Rule {
            id: Uuid::now_v7().to_string(),
            name: "zone2-to-zone1".to_string(),
            zone_pair_id: zq.to_string(),
            priority: 0,
            content: allow_v4.to_string(),
            smtp_matchers: None,
        },
    ];

    ConfigBundleBuilder::new()
        .with_zones(zones)
        .with_zone_pairs(zone_pairs)
        .with_zone_interfaces(zone_interfaces)
        .with_rules(rules)
        .build()
}

pub fn dual_zone_allow_ipv4_smtp_bundle(smtp_matchers: SmtpMatchers) -> ConfigBundle {
    let z1 = Uuid::now_v7();
    let z2 = Uuid::now_v7();
    let zp = Uuid::now_v7();
    let zq = Uuid::now_v7();
    let zi1 = Uuid::now_v7();
    let zi2 = Uuid::now_v7();

    let zones = vec![
        Zone {
            id: Uuid::nil().to_string(),
            name: "default".to_string(),
        },
        Zone {
            id: z1.to_string(),
            name: "zone1".to_string(),
        },
        Zone {
            id: z2.to_string(),
            name: "zone2".to_string(),
        },
    ];

    let zone_interfaces = vec![
        physical_zone_interface(zi1, &z1.to_string(), "eth1", true),
        physical_zone_interface(zi2, &z2.to_string(), "eth2", true),
    ];

    let zone_pairs = vec![
        ZonePair {
            id: zp.to_string(),
            src_zone_id: z1.to_string(),
            dst_zone_id: z2.to_string(),
            default_policy: DefaultPolicy::Unspecified as i32,
        },
        ZonePair {
            id: zq.to_string(),
            src_zone_id: z2.to_string(),
            dst_zone_id: z1.to_string(),
            default_policy: DefaultPolicy::Unspecified as i32,
        },
    ];

    let allow_v4 = r#"
            match ip_ver {
              =v4: verdict allow
              =v6: verdict drop
            }
          "#;

    let rules = vec![
        Rule {
            id: Uuid::now_v7().to_string(),
            name: "zone1-to-zone2".to_string(),
            zone_pair_id: zp.to_string(),
            priority: 0,
            content: allow_v4.to_string(),
            smtp_matchers: Some(smtp_matchers),
        },
        Rule {
            id: Uuid::now_v7().to_string(),
            name: "zone2-to-zone1".to_string(),
            zone_pair_id: zq.to_string(),
            priority: 0,
            content: allow_v4.to_string(),
            smtp_matchers: None,
        },
    ];

    ConfigBundleBuilder::new()
        .with_zones(zones)
        .with_zone_pairs(zone_pairs)
        .with_zone_interfaces(zone_interfaces)
        .with_rules(rules)
        .build()
}

pub fn default_zone_dual_iface_dst_port_rule_bundle() -> ConfigBundle {
    let def = Uuid::nil().to_string();
    let zp = Uuid::nil().to_string();
    let zi1 = Uuid::now_v7();
    let zi2 = Uuid::now_v7();

    let zones = vec![Zone {
        id: def.clone(),
        name: "default".to_string(),
    }];

    let zone_interfaces = vec![
        physical_zone_interface(zi1, &def, "eth1", true),
        physical_zone_interface(zi2, &def, "eth2", true),
    ];

    let zone_pairs = vec![ZonePair {
        id: zp.clone(),
        src_zone_id: def.clone(),
        dst_zone_id: def.clone(),
        default_policy: DefaultPolicy::Unspecified as i32,
    }];

    let rules = vec![Rule {
        id: Uuid::now_v7().to_string(),
        name: "dst-port-filter".to_string(),
        zone_pair_id: zp,
        priority: 0,
        content: r#"match dst_port {
            =12345: verdict drop
            _: verdict allow
        }"#
        .to_string(),
        smtp_matchers: None,
    }];

    ConfigBundleBuilder::new()
        .with_zones(zones)
        .with_zone_pairs(zone_pairs)
        .with_zone_interfaces(zone_interfaces)
        .with_rules(rules)
        .build()
}
