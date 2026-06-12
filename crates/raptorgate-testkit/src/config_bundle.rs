use ngfw::proto::common::DefaultPolicy;
use ngfw::proto::config::{
    InterfaceStatus, PhysicalInterface, Rule, SshMatch, SshMatchAction, SshMatchers, Zone,
    ZoneInterface, ZonePair,
};
use ngfw::proto::services::ConfigBundle;
use uuid::Uuid;

pub fn smoke_tcp_allow_warn_bundle_with_ssh(ssh_matchers: SshMatchers) -> ConfigBundle {
    let mut bundle = smoke_tcp_allow_warn_bundle();
    for rule in &mut bundle.rules {
        rule.ssh_matchers = Some(ssh_matchers.clone());
    }
    bundle
}

pub fn permissive_ssh_matchers() -> SshMatchers {
    let allow = SshMatch {
        regex: ".*".to_string(),
        on_match: SshMatchAction::Allow as i32,
    };
    SshMatchers {
        client_software: vec![allow.clone()],
        server_software: vec![allow.clone()],
        client_proto_version: vec![allow.clone()],
        server_proto_version: vec![allow.clone()],
        kex: vec![allow.clone()],
        host_key_alg: vec![allow.clone()],
        cipher: vec![allow.clone()],
        mac: vec![allow.clone()],
        compression: vec![allow.clone()],
        host_key_type: vec![allow],
        disconnect_reason: vec![],
    }
}

pub struct ConfigBundleBuilder {
    inner: ConfigBundle,
}

impl Default for ConfigBundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigBundleBuilder {
    pub fn new() -> Self {
        let default_zone = Zone {
            id: Uuid::nil().to_string(),
            name: "default".to_string(),
        };
        let src_zone = Zone {
            id: Uuid::now_v7().to_string(),
            name: "zone1".to_string(),
        };
        let dst_zone = Zone {
            id: Uuid::now_v7().to_string(),
            name: "zone2".to_string(),
        };
        let zone_pair = ZonePair {
            id: Uuid::now_v7().to_string(),
            src_zone_id: src_zone.id.clone(),
            dst_zone_id: dst_zone.id.clone(),
            default_policy: DefaultPolicy::Unspecified as i32,
        };
        let rule = Rule {
            id: Uuid::now_v7().to_string(),
            name: "default_e2e_testing".to_string(),
            zone_pair_id: zone_pair.id.clone(),
            priority: 0,
            content: r#"
		match ip_ver {
			=v4: match protocol {
				|(=icmp =tcp =udp): verdict allow
			}
			= v6: verdict drop
		}
	"#
            .to_string(),
            smtp_matchers: None,
            ssh_matchers: None,
        };

        Self {
            inner: ConfigBundle {
                rules: vec![rule],
                zones: vec![default_zone, src_zone, dst_zone],
                zone_pairs: vec![zone_pair],
                zone_interfaces: vec![],
                ..Default::default()
            },
        }
    }

    pub fn with_rules(mut self, rules: Vec<Rule>) -> Self {
        self.inner.rules = rules;
        self
    }

    pub fn with_zones(mut self, zones: Vec<Zone>) -> Self {
        self.inner.zones = zones;
        self
    }

    pub fn with_zone_pairs(mut self, zone_pairs: Vec<ZonePair>) -> Self {
        self.inner.zone_pairs = zone_pairs;
        self
    }

    pub fn with_zone_interfaces(mut self, zone_interfaces: Vec<ZoneInterface>) -> Self {
        self.inner.zone_interfaces = zone_interfaces;
        self
    }

    pub fn with_nat_rules(mut self, nat_rules: Vec<ngfw::proto::config::NatRule>) -> Self {
        self.inner.nat_rules = nat_rules;
        self
    }

    pub fn with_app_config(mut self, app: ngfw::proto::config::AppConfig) -> Self {
        self.inner.app_config = Some(app);
        self
    }

    pub fn build(self) -> ConfigBundle {
        self.inner
    }
}

pub fn physical_zone_interface(
    id: Uuid,
    zone_id: &str,
    interface_name: &str,
    sniffed: bool,
) -> ZoneInterface {
    ZoneInterface {
        id: id.to_string(),
        zone_id: zone_id.to_string(),
        status: InterfaceStatus::Unspecified as i32,
        addresses: vec![],
        kind: Some(ngfw::proto::config::zone_interface::Kind::Physical(
            PhysicalInterface {
                interface_name: interface_name.to_string(),
            },
        )),
        sniffed,
    }
}

pub fn smoke_icmp_allow_warn_bundle() -> ConfigBundle {
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

    let rules = vec![
        Rule {
            id: Uuid::now_v7().to_string(),
            name: "zone1-to-zone2".to_string(),
            zone_pair_id: zp.to_string(),
            priority: 0,
            content: r#"
            match protocol {
              =icmp: verdict allow_warn "icmp allowed"
              =tcp: verdict drop_warn "tcp dropped"
              =udp: verdict drop_warn "udp dropped"
            }
          "#
            .to_string(),
            smtp_matchers: None,
            ssh_matchers: None,
        },
        Rule {
            id: Uuid::now_v7().to_string(),
            name: "zone2-to-zone1".to_string(),
            zone_pair_id: zq.to_string(),
            priority: 0,
            content: r#"
            match protocol {
              =icmp: verdict allow_warn "icmp allowed"
              =tcp: verdict drop_warn "tcp dropped"
              =udp: verdict drop_warn "udp dropped"
            }
          "#
            .to_string(),
            smtp_matchers: None,
            ssh_matchers: None,
        },
    ];

    ConfigBundleBuilder::new()
        .with_zones(zones)
        .with_zone_pairs(zone_pairs)
        .with_zone_interfaces(zone_interfaces)
        .with_rules(rules)
        .build()
}

pub fn smoke_tcp_allow_warn_bundle() -> ConfigBundle {
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

    let rules = vec![
        Rule {
            id: Uuid::now_v7().to_string(),
            name: "zone1-to-zone2".to_string(),
            zone_pair_id: zp.to_string(),
            priority: 0,
            content: r#"
            match protocol {
              =icmp: verdict drop_warn "icmp dropped"
              =tcp: verdict allow_warn "tcp allowed"
              =udp: verdict drop_warn "udp dropped"
            }
          "#
            .to_string(),
            smtp_matchers: None,
            ssh_matchers: Some(permissive_ssh_matchers()),
        },
        Rule {
            id: Uuid::now_v7().to_string(),
            name: "zone2-to-zone1".to_string(),
            zone_pair_id: zq.to_string(),
            priority: 0,
            content: r#"
            match protocol {
              =icmp: verdict drop_warn "icmp dropped"
              =tcp: verdict allow_warn "tcp allowed"
              =udp: verdict drop_warn "udp dropped"
            }
          "#
            .to_string(),
            smtp_matchers: None,
            ssh_matchers: Some(permissive_ssh_matchers()),
        },
    ];

    ConfigBundleBuilder::new()
        .with_zones(zones)
        .with_zone_pairs(zone_pairs)
        .with_zone_interfaces(zone_interfaces)
        .with_rules(rules)
        .build()
}
