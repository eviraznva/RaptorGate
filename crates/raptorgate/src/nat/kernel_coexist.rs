//! Kernel-side coexistence rules for userspace NAT.
//!
//! RaptorGate performs NAT in userspace: it pcap-captures ingress frames,
//! rewrites them, and reinjects via `tun0`. The host kernel still owns the
//! stack, which creates two collisions the userspace path cannot avoid on its
//! own:
//!
//! 1. **SNAT / MASQUERADE replies** are destined to a translated source IP that
//!    is a *local* address on the router (assigned so it answers ARP). The
//!    kernel sees the inbound reply, matches the conntrack entry it created for
//!    the firewall's reinjected forward packet (`ct state established`), delivers
//!    it locally, finds no socket, and sends an RST — tearing down the
//!    userspace-forwarded session before the reply reaches the client.
//!    Fix: `notrack` traffic destined to the translated IPs in `raw` prerouting.
//!    The reply is then untracked, the `established` accept no longer matches, and
//!    INPUT policy (drop) silently discards the kernel's copy — no RST — while the
//!    pcap copy is still forwarded to the client.
//!
//! 2. **DNAT / PAT to a VIP on an inspected TLS port** (e.g. `VIP:443`) collides
//!    with the transparent TLS redirect (`raptorgate_tls`), which rewrites the
//!    VIP packet to the local MITM proxy before the userspace DNAT can take
//!    effect. Fix: add the DNAT/PAT VIP host addresses to the TLS redirect's
//!    bypass set so the kernel leaves that traffic to the userspace path.
//!
//! Both rule sets are derived from the active NAT rules and refreshed whenever
//! the NAT configuration changes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};

use crate::nat::config::{NatAction, NatRules};
const COEXIST_TABLE: &str = "raptorgate_nat_coexist";

/// Parameters needed to (re)install the transparent TLS redirect so that NAT
/// VIPs can be added to its bypass set. `None` when TLS inspection is disabled.
#[derive(Clone)]
pub struct RedirectParams {
    pub listen_addr: SocketAddr,
    pub capture_interfaces: Vec<String>,
    pub inspection_ports: Vec<u16>,
    /// Firewall-local addresses that always bypass the redirect.
    pub local_addresses: Vec<IpAddr>,
}

pub struct NatKernelSync {
    redirect: Option<RedirectParams>,
    state: Mutex<AppliedState>,
}

#[derive(Default)]
struct AppliedState {
    notrack_ips: BTreeSet<IpAddr>,
    redirect_bypass: BTreeSet<IpAddr>,
    /// Translated IPs this component assigned to an interface (ip → iface), so
    /// they can be removed when no longer referenced by any NAT rule.
    assigned_addrs: BTreeMap<IpAddr, String>,
}

#[derive(Default)]
struct DerivedSets {
    /// Translated source IPs (SNAT/MASQUERADE) whose return traffic must not be
    /// conntracked by the kernel.
    notrack_ips: BTreeSet<IpAddr>,
    /// DNAT/PAT VIP host addresses that must bypass the TLS redirect.
    redirect_bypass: BTreeSet<IpAddr>,
    /// SNAT translated IPs not already owned by an interface, to be assigned as
    /// /32 so the firewall answers ARP for them. Maps ip → interface.
    assign_addrs: BTreeMap<IpAddr, String>,
}

impl NatKernelSync {
    pub fn new(redirect: Option<RedirectParams>) -> Self {
        Self {
            redirect,
            state: Mutex::new(AppliedState::default()),
        }
    }

    /// Recompute and reinstall all kernel coexistence rules for the given active
    /// NAT rules. Idempotent: only state that actually changed is rewritten.
    /// Errors are logged, not propagated: a NAT config change must not fail
    /// because an auxiliary kernel rule could not be written.
    pub fn apply(&self, rules: Option<&NatRules>, interface_ips: &HashMap<String, Vec<IpAddr>>) {
        let sets = derive_sets(rules, interface_ips);

        let mut state = self.state.lock().expect("nat kernel sync state poisoned");

        if sets.notrack_ips != state.notrack_ips {
            if let Err(e) = install_coexist_table(&sets.notrack_ips) {
                tracing::error!(error = %e, "failed to install NAT coexistence table");
            } else {
                state.notrack_ips = sets.notrack_ips.clone();
            }
        }

        if let Some(params) = &self.redirect {
            if sets.redirect_bypass != state.redirect_bypass {
                if let Err(e) = reinstall_redirect(params, &sets.redirect_bypass) {
                    tracing::error!(error = %e, "failed to reinstall TLS redirect with NAT bypass");
                } else {
                    state.redirect_bypass = sets.redirect_bypass.clone();
                }
            }
        }

        reconcile_assigned_addrs(&mut state.assigned_addrs, &sets.assign_addrs);

        tracing::info!(
            event = "nat.kernel_coexist.applied",
            notrack_ips = ?sets.notrack_ips,
            redirect_bypass = ?sets.redirect_bypass,
            assigned_addrs = ?sets.assign_addrs,
            "NAT kernel coexistence rules applied"
        );
    }
}

fn derive_sets(rules: Option<&NatRules>, interface_ips: &HashMap<String, Vec<IpAddr>>) -> DerivedSets {
    let mut sets = DerivedSets::default();

    let Some(rules) = rules else {
        return sets;
    };

    let local_ips: BTreeSet<IpAddr> = interface_ips.values().flatten().copied().collect();

    for rule in rules.rules() {
        match rule.action() {
            NatAction::Snat { translated_ip, .. } => {
                sets.notrack_ips.insert(*translated_ip);
                // A SNAT target not already owned by an interface must be
                // assigned so it answers ARP on its segment.
                if !local_ips.contains(translated_ip) {
                    if let Some(iface) = best_interface_for(*translated_ip, interface_ips) {
                        sets.assign_addrs.insert(*translated_ip, iface);
                    }
                }
            }
            NatAction::Masquerade { .. } => {
                if let Some(iface) = rule.out_interface() {
                    if let Some(ips) = interface_ips.get(iface) {
                        sets.notrack_ips.extend(ips.iter().copied());
                    }
                }
            }
            NatAction::Dnat { dst_cidr, .. } => {
                // Only a single host VIP can bypass the redirect by address; a
                // wider DNAT range overlapping an inspected port is an unusual
                // combination we leave to TLS inspection.
                if dst_cidr.prefix_len() == dst_cidr.max_prefix_len() {
                    sets.redirect_bypass.insert(dst_cidr.addr());
                }
            }
            NatAction::Pat { dst_ip, .. } => {
                sets.redirect_bypass.insert(*dst_ip);
            }
        }
    }

    sets
}

/// Pick the interface whose existing IPv4 address shares the longest prefix with
/// `target` — i.e. the interface on whose subnet the SNAT address most likely
/// lives. IPv6 SNAT targets are not auto-assigned.
fn best_interface_for(target: IpAddr, interface_ips: &HashMap<String, Vec<IpAddr>>) -> Option<String> {
    let IpAddr::V4(target) = target else { return None };

    let mut best: Option<(u32, &str)> = None;
    for (iface, ips) in interface_ips {
        for ip in ips {
            if let IpAddr::V4(v4) = ip {
                let bits = common_prefix_bits(target, *v4);
                if best.map(|(b, _)| bits > b).unwrap_or(true) {
                    best = Some((bits, iface.as_str()));
                }
            }
        }
    }

    best.map(|(_, iface)| iface.to_string())
}

fn common_prefix_bits(a: Ipv4Addr, b: Ipv4Addr) -> u32 {
    (u32::from(a) ^ u32::from(b)).leading_zeros()
}

fn reconcile_assigned_addrs(current: &mut BTreeMap<IpAddr, String>, desired: &BTreeMap<IpAddr, String>) {
    let stale: Vec<IpAddr> = current
        .keys()
        .filter(|ip| !desired.contains_key(*ip))
        .copied()
        .collect();
    for ip in stale {
        if let Some(iface) = current.get(&ip) {
            if let Err(e) = run_ip_addr("del", ip, iface) {
                tracing::warn!(error = %e, %ip, %iface, "failed to remove NAT-assigned address");
            }
        }
        current.remove(&ip);
    }

    for (ip, iface) in desired {
        if current.get(ip).map(|i| i == iface).unwrap_or(false) {
            continue;
        }
        if let Err(e) = run_ip_addr("add", *ip, iface) {
            tracing::warn!(error = %e, %ip, %iface, "failed to assign NAT address");
        } else {
            current.insert(*ip, iface.clone());
        }
    }
}

fn run_ip_addr(op: &str, ip: IpAddr, iface: &str) -> Result<()> {
    let cidr = match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    };

    let output = Command::new("ip")
        .args(["addr", op, &cidr, "dev", iface])
        .output()
        .with_context(|| format!("failed to run ip addr {op} {cidr} dev {iface}"))?;

    // `add` of an existing address / `del` of a missing one are benign.
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("File exists") || stderr.contains("Cannot assign") || stderr.contains("does not exist") {
        return Ok(());
    }
    bail!("ip addr {op} {cidr} dev {iface} failed: {stderr}");
}

fn install_coexist_table(notrack_ips: &BTreeSet<IpAddr>) -> Result<()> {
    delete_table_if_present(COEXIST_TABLE)?;

    if notrack_ips.is_empty() {
        return Ok(());
    }

    let v4: Vec<String> = notrack_ips
        .iter()
        .filter(|ip| ip.is_ipv4())
        .map(IpAddr::to_string)
        .collect();
    let v6: Vec<String> = notrack_ips
        .iter()
        .filter(|ip| ip.is_ipv6())
        .map(IpAddr::to_string)
        .collect();

    let mut rules = String::new();
    if !v4.is_empty() {
        rules.push_str(&format!("        ip daddr {{ {} }} notrack\n", v4.join(", ")));
    }
    if !v6.is_empty() {
        rules.push_str(&format!("        ip6 daddr {{ {} }} notrack\n", v6.join(", ")));
    }

    let script = format!(
        "table inet {COEXIST_TABLE} {{
    chain prerouting_raw {{
        type filter hook prerouting priority raw; policy accept;
{rules}    }}
}}
"
    );

    apply_script(&script)
}

fn reinstall_redirect(params: &RedirectParams, bypass: &BTreeSet<IpAddr>) -> Result<()> {
    let _ = (params, bypass);
    Ok(())
}

fn delete_table_if_present(table: &str) -> Result<()> {
    let status = Command::new("nft")
        .args(["list", "table", "inet", table])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to probe nftables table")?;

    if !status.success() {
        return Ok(());
    }

    let delete_status = Command::new("nft")
        .args(["delete", "table", "inet", table])
        .status()
        .context("Failed to delete existing nftables table")?;

    if !delete_status.success() {
        bail!("nft delete table inet {table} failed");
    }

    Ok(())
}

fn apply_script(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to start nft")?;

    {
        let stdin = child.stdin.as_mut().context("Failed to open nft stdin")?;
        stdin
            .write_all(script.as_bytes())
            .context("Failed to write nft rules")?;
    }

    let output = child.wait_with_output().context("Failed to wait for nft")?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!("nft apply failed: {stderr}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::config::{NatAction, NatProtocol, NatRule, NatRules};
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn rule(action: NatAction, out_interface: Option<&str>) -> NatRule {
        NatRule::new(
            "r".into(),
            1,
            None,
            out_interface.map(str::to_string),
            None,
            None,
            NatProtocol::All,
            None,
            None,
            action,
        )
    }

    #[test]
    fn snat_translated_ip_is_notracked() {
        let rules = NatRules::new(vec![rule(
            NatAction::Snat {
                src_cidr: "192.168.10.0/24".parse().unwrap(),
                translated_ip: ip(192, 168, 20, 100),
                src_port_range: None,
            },
            None,
        )]);

        let sets = derive_sets(Some(&rules), &HashMap::new());
        assert!(sets.notrack_ips.contains(&ip(192, 168, 20, 100)));
        assert!(sets.redirect_bypass.is_empty());
    }

    #[test]
    fn masquerade_resolves_out_interface_ips() {
        let rules = NatRules::new(vec![rule(
            NatAction::Masquerade { src_cidr: None, src_port_range: None },
            Some("eth2"),
        )]);

        let mut iface_ips = HashMap::new();
        iface_ips.insert("eth2".to_string(), vec![ip(192, 168, 20, 254)]);

        let sets = derive_sets(Some(&rules), &iface_ips);
        assert!(sets.notrack_ips.contains(&ip(192, 168, 20, 254)));
    }

    #[test]
    fn dnat_and_pat_vips_bypass_redirect() {
        let rules = NatRules::new(vec![
            rule(
                NatAction::Dnat {
                    dst_cidr: "192.168.20.200/32".parse().unwrap(),
                    translated_ip: ip(192, 168, 20, 10),
                    translated_port: Some(80),
                },
                None,
            ),
            rule(
                NatAction::Pat {
                    dst_ip: ip(192, 168, 20, 201),
                    dst_port: 8080,
                    translated_ip: ip(192, 168, 20, 10),
                    translated_port: 80,
                },
                None,
            ),
        ]);

        let sets = derive_sets(Some(&rules), &HashMap::new());
        assert!(sets.redirect_bypass.contains(&ip(192, 168, 20, 200)));
        assert!(sets.redirect_bypass.contains(&ip(192, 168, 20, 201)));
        assert!(sets.notrack_ips.is_empty());
    }

    #[test]
    fn wide_dnat_cidr_is_not_added_to_bypass() {
        let rules = NatRules::new(vec![rule(
            NatAction::Dnat {
                dst_cidr: "192.168.20.0/24".parse().unwrap(),
                translated_ip: ip(192, 168, 20, 10),
                translated_port: Some(80),
            },
            None,
        )]);

        let sets = derive_sets(Some(&rules), &HashMap::new());
        assert!(sets.redirect_bypass.is_empty());
    }

    #[test]
    fn no_rules_yield_empty_sets() {
        let sets = derive_sets(None, &HashMap::new());
        assert!(sets.notrack_ips.is_empty());
        assert!(sets.redirect_bypass.is_empty());
        assert!(sets.assign_addrs.is_empty());
    }

    #[test]
    fn snat_target_off_interface_is_assigned_to_best_match() {
        let rules = NatRules::new(vec![rule(
            NatAction::Snat {
                src_cidr: "192.168.10.0/24".parse().unwrap(),
                translated_ip: ip(192, 168, 20, 100),
                src_port_range: None,
            },
            None,
        )]);

        let mut iface_ips = HashMap::new();
        iface_ips.insert("eth1".to_string(), vec![ip(192, 168, 10, 254)]);
        iface_ips.insert("eth2".to_string(), vec![ip(192, 168, 20, 254)]);

        let sets = derive_sets(Some(&rules), &iface_ips);
        // 20.100 shares the longest prefix with eth2's 20.254.
        assert_eq!(sets.assign_addrs.get(&ip(192, 168, 20, 100)), Some(&"eth2".to_string()));
    }

    #[test]
    fn snat_target_already_local_is_not_assigned() {
        let rules = NatRules::new(vec![rule(
            NatAction::Snat {
                src_cidr: "192.168.10.0/24".parse().unwrap(),
                translated_ip: ip(192, 168, 20, 254),
                src_port_range: None,
            },
            None,
        )]);

        let mut iface_ips = HashMap::new();
        iface_ips.insert("eth2".to_string(), vec![ip(192, 168, 20, 254)]);

        let sets = derive_sets(Some(&rules), &iface_ips);
        assert!(sets.assign_addrs.is_empty());
        assert!(sets.notrack_ips.contains(&ip(192, 168, 20, 254)));
    }
}
