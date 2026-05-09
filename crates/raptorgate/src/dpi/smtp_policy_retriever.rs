use std::net::IpAddr;
use std::sync::Arc;

use crate::policy::{provider::DiskPolicyProvider, SmtpPolicy};
use crate::zones::resolver::ZoneResolver;

#[derive(Clone, Debug)]
pub struct SmtpSessionPolicies {
    pub client_to_server: Vec<SmtpPolicy>,
    pub server_to_client: Vec<SmtpPolicy>,
}

pub struct SmtpPolicyRetriever<ZR> {
    zone_resolver: Arc<ZR>,
    policy_provider: Arc<DiskPolicyProvider>,
}

impl<ZR: ZoneResolver> SmtpPolicyRetriever<ZR> {
    pub fn new(zone_resolver: Arc<ZR>, policy_provider: Arc<DiskPolicyProvider>) -> Self {
        Self {
            zone_resolver,
            policy_provider,
        }
    }

    pub fn retrieve(&self, client_ip: IpAddr, server_ip: IpAddr) -> SmtpSessionPolicies {
        let pairs = self.zone_resolver.resolve_bidirectional(client_ip, server_ip);
        let policies = self.policy_provider.get_policies();

        let mut client_to_server = Vec::new();
        let mut server_to_client = Vec::new();

        for policy in policies.values() {
            if let Some(ref forward) = pairs.forward {
                if policy.zone_pair_id == forward.id {
                    client_to_server.push(policy.smtp_policy.clone());
                }
            }
            if let Some(ref reverse) = pairs.reverse {
                if policy.zone_pair_id == reverse.id {
                    server_to_client.push(policy.smtp_policy.clone());
                }
            }
        }

        SmtpSessionPolicies {
            client_to_server,
            server_to_client,
        }
    }
}
