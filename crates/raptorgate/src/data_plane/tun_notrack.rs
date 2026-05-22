use std::collections::BTreeSet;
use std::hash::BuildHasher;
use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use ipnet::IpNet;

use crate::zones::{ZoneInterface, ZoneInterfaceId};

const TABLE_FAMILY: &str = "inet";
const TABLE_NAME: &str = "raptorgate_tun_notrack";

pub fn install_for_zone_interfaces<S>(
    tun_name: &str,
    zone_interfaces: &std::collections::HashMap<ZoneInterfaceId, ZoneInterface, S>,
) -> Result<()>
where
    S: BuildHasher,
{
    install(tun_name, prefixes_from_zone_interfaces(zone_interfaces))
}

fn install(tun_name: &str, prefixes: impl IntoIterator<Item = IpNet>) -> Result<()> {
    let prefixes = normalize_prefixes(prefixes);
    let _ = Command::new("nft")
        .args(["delete", "table", TABLE_FAMILY, TABLE_NAME])
        .status();

    if prefixes.is_empty() {
        return Ok(());
    }

    apply_script(&render_script(tun_name, &prefixes))
}

fn prefixes_from_zone_interfaces<S>(
    zone_interfaces: &std::collections::HashMap<ZoneInterfaceId, ZoneInterface, S>,
) -> Vec<IpNet>
where
    S: BuildHasher,
{
    zone_interfaces
        .values()
        .flat_map(|zi| zi.addresses.iter())
        .filter_map(|addr| addr.parse::<IpNet>().ok())
        .collect()
}

fn normalize_prefixes(prefixes: impl IntoIterator<Item = IpNet>) -> Vec<IpNet> {
    prefixes
        .into_iter()
        .map(|net| net.trunc())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn apply_script(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to spawn nft")?;

    let stdin = child.stdin.as_mut().context("failed to open nft stdin")?;
    stdin.write_all(script.as_bytes()).context("failed to write nft script")?;

    let status = child.wait().context("failed to wait for nft")?;
    anyhow::ensure!(status.success(), "nft returned status {status}");
    Ok(())
}

fn render_script(tun_name: &str, prefixes: &[IpNet]) -> String {
    let tun_name = nft_string(tun_name);
    let mut out = format!("table {TABLE_FAMILY} {TABLE_NAME} {{\n\tchain prerouting {{\n\t\ttype filter hook prerouting priority raw; policy accept;\n");

    for prefix in prefixes {
        let family = match prefix {
            IpNet::V4(_) => "ip",
            IpNet::V6(_) => "ip6",
        };
        out.push_str(&format!("\t\tiifname {tun_name} {family} daddr {prefix} notrack\n"));
    }

    out.push_str("\t}\n}\n");
    out
}

fn nft_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zones::{InterfaceStatus, PhysicalInterface, ZoneId, ZoneInterfaceKind};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn render_script_adds_notrack_for_ipv4_and_ipv6_prefixes() {
        let prefixes = normalize_prefixes([
            "192.168.20.254/24".parse::<IpNet>().unwrap(),
            "2001:db8::1/64".parse::<IpNet>().unwrap(),
        ]);

        let script = render_script("tun0", &prefixes);

        assert!(script.contains("table inet raptorgate_tun_notrack"));
        assert!(script.contains("iifname \"tun0\" ip daddr 192.168.20.0/24 notrack"));
        assert!(script.contains("iifname \"tun0\" ip6 daddr 2001:db8::/64 notrack"));
    }

    #[test]
    fn prefixes_from_zone_interfaces_ignores_invalid_addresses() {
        let mut zones = HashMap::new();
        zones.insert(
            ZoneInterfaceId::from(Uuid::from_u128(1)),
            ZoneInterface {
                zone_id: ZoneId::from(Uuid::from_u128(2)),
                kind: ZoneInterfaceKind::Physical(PhysicalInterface {
                    interface_name: "eth2".into(),
                }),
                status: InterfaceStatus::Active,
                addresses: vec!["192.168.20.254/24".into(), "bad".into()],
                sniffed: true,
            },
        );

        let prefixes = normalize_prefixes(prefixes_from_zone_interfaces(&zones));

        assert_eq!(prefixes, vec!["192.168.20.0/24".parse::<IpNet>().unwrap()]);
    }
}
