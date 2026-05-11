use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

const TABLE_NAME: &str = "raptorgate_tls";

// Adresy interfejsow firewalla — ruch na nie to zone-to-self, omija decryption.
pub struct TransparentRedirect {
    listen_addr: SocketAddr,
    capture_interfaces: Vec<String>,
    inspection_ports: Vec<u16>,
    local_addresses_v4: Vec<Ipv4Addr>,
    local_addresses_v6: Vec<Ipv6Addr>,
}

impl TransparentRedirect {
    pub fn new(
        listen_addr: SocketAddr,
        capture_interfaces: Vec<String>,
        inspection_ports: Vec<u16>,
        local_addresses: Vec<IpAddr>,
    ) -> Result<Self> {
        let capture_interfaces: Vec<String> = capture_interfaces
            .into_iter()
            .map(|iface| iface.trim().to_string())
            .filter(|iface| !iface.is_empty())
            .collect();

        if capture_interfaces.is_empty() {
            bail!("TLS redirect needs at least one capture interface");
        }

        let mut inspection_ports = inspection_ports;
        inspection_ports.sort_unstable();
        inspection_ports.dedup();

        if inspection_ports.is_empty() {
            bail!("TLS redirect needs at least one inspection port");
        }

        let mut local_addresses_v4: Vec<Ipv4Addr> = local_addresses
            .iter()
            .filter_map(|addr| match addr {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .collect();
        local_addresses_v4.sort_unstable();
        local_addresses_v4.dedup();

        let mut local_addresses_v6: Vec<Ipv6Addr> = local_addresses
            .iter()
            .filter_map(|addr| match addr {
                IpAddr::V4(_) => None,
                IpAddr::V6(v6) => Some(*v6),
            })
            .collect();
        local_addresses_v6.sort_unstable();
        local_addresses_v6.dedup();

        Ok(Self {
            listen_addr,
            capture_interfaces,
            inspection_ports,
            local_addresses_v4,
            local_addresses_v6,
        })
    }

    // Instaluje reguły redirectu dla transparentnego przechwycenia TLS.
    pub fn install(&self) -> Result<()> {
        let script = self.render_script();

        self.delete_table_if_present()?;
        self.apply_script(&script)?;

        tracing::info!(
            listen_addr = %self.listen_addr,
            interfaces = ?self.capture_interfaces,
            ports = ?self.inspection_ports,
            "TLS transparent redirect installed"
        );

        Ok(())
    }

    fn delete_table_if_present(&self) -> Result<()> {
        let status = Command::new("nft")
            .args(["list", "table", "inet", TABLE_NAME])
            .status()
            .context("Failed to probe nftables table")?;

        if !status.success() {
            return Ok(());
        }

        let delete_status = Command::new("nft")
            .args(["delete", "table", "inet", TABLE_NAME])
            .status()
            .context("Failed to delete existing nftables table")?;

        if !delete_status.success() {
            bail!("nft delete table inet {TABLE_NAME} failed");
        }

        Ok(())
    }

    fn apply_script(&self, script: &str) -> Result<()> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start nft")?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .context("Failed to open nft stdin")?;
            stdin
                .write_all(script.as_bytes())
                .context("Failed to write nft rules")?;
        }

        let output = child
            .wait_with_output()
            .context("Failed to wait for nft")?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nft apply failed: {stderr}");
    }

    fn render_script(&self) -> String {
        let interfaces = self
            .capture_interfaces
            .iter()
            .map(|iface| format!("\"{iface}\""))
            .collect::<Vec<_>>()
            .join(", ");

        let ports = self
            .inspection_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");

        let listen_port = self.listen_addr.port();

        let mut bypass_rules = String::new();

        if !self.local_addresses_v4.is_empty() {
            let addrs = self
                .local_addresses_v4
                .iter()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            bypass_rules.push_str(&format!(
                "        iifname {{ {interfaces} }} tcp dport {{ {ports} }} ip daddr {{ {addrs} }} return\n"
            ));
        }

        if !self.local_addresses_v6.is_empty() {
            let addrs = self
                .local_addresses_v6
                .iter()
                .map(Ipv6Addr::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            bypass_rules.push_str(&format!(
                "        iifname {{ {interfaces} }} tcp dport {{ {ports} }} ip6 daddr {{ {addrs} }} return\n"
            ));
        }

        format!(
            "table inet {TABLE_NAME} {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
{bypass_rules}        iifname {{ {interfaces} }} tcp dport {{ {ports} }} redirect to :{listen_port}
    }}
}}
"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_interfaces() {
        let result = TransparentRedirect::new(
            "127.0.0.1:8443".parse().unwrap(),
            vec![],
            vec![443],
            vec![],
        );
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_empty_inspection_ports() {
        let result = TransparentRedirect::new(
            "127.0.0.1:8443".parse().unwrap(),
            vec!["eth1".into()],
            vec![],
            vec![],
        );
        assert!(result.is_err());
    }

    #[test]
    fn render_script_contains_interfaces_and_port() {
        let redirect = TransparentRedirect::new(
            "0.0.0.0:9443".parse().unwrap(),
            vec!["eth1".into(), "eth2".into()],
            vec![443],
            vec![],
        )
        .unwrap();

        let script = redirect.render_script();

        assert!(script.contains("table inet raptorgate_tls"));
        assert!(script.contains("iifname { \"eth1\", \"eth2\" }"));
        assert!(script.contains("tcp dport { 443 }"));
        assert!(script.contains("redirect to :9443"));
    }

    #[test]
    fn render_script_contains_custom_port_set() {
        let redirect = TransparentRedirect::new(
            "0.0.0.0:9443".parse().unwrap(),
            vec!["eth1".into()],
            vec![8443, 443, 993, 443],
            vec![],
        )
        .unwrap();

        let script = redirect.render_script();

        assert!(script.contains("tcp dport { 443, 993, 8443 }"));
    }

    #[test]
    fn render_script_bypasses_local_v4_addresses() {
        let redirect = TransparentRedirect::new(
            "0.0.0.0:9443".parse().unwrap(),
            vec!["eth1".into()],
            vec![443],
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 10, 254)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 56, 254)),
            ],
        )
        .unwrap();

        let script = redirect.render_script();

        assert!(script.contains("ip daddr { 192.168.10.254, 192.168.56.254 } return"));
        assert!(script.contains("redirect to :9443"));
        assert!(!script.contains("ip daddr !="));
    }

    #[test]
    fn render_script_bypasses_local_v6_addresses() {
        let redirect = TransparentRedirect::new(
            "0.0.0.0:9443".parse().unwrap(),
            vec!["eth1".into()],
            vec![443],
            vec![IpAddr::V6("fe80::1".parse().unwrap())],
        )
        .unwrap();

        let script = redirect.render_script();

        assert!(script.contains("ip6 daddr { fe80::1 } return"));
    }

    #[test]
    fn render_script_emits_bypass_per_family() {
        let redirect = TransparentRedirect::new(
            "0.0.0.0:9443".parse().unwrap(),
            vec!["eth1".into()],
            vec![443],
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 10, 254)),
                IpAddr::V6("fe80::1".parse().unwrap()),
            ],
        )
        .unwrap();

        let script = redirect.render_script();

        assert!(script.contains("ip daddr { 192.168.10.254 } return"));
        assert!(script.contains("ip6 daddr { fe80::1 } return"));
        assert!(!script.contains("ip daddr { 192.168.10.254 } ip6"));
    }

    #[test]
    fn render_script_omits_bypass_when_no_local_addresses() {
        let redirect = TransparentRedirect::new(
            "0.0.0.0:9443".parse().unwrap(),
            vec!["eth1".into()],
            vec![443],
            vec![],
        )
        .unwrap();

        let script = redirect.render_script();

        assert!(!script.contains("return"));
    }

    #[test]
    fn new_deduplicates_local_addresses() {
        let redirect = TransparentRedirect::new(
            "0.0.0.0:9443".parse().unwrap(),
            vec!["eth1".into()],
            vec![443],
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 10, 254)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 10, 254)),
            ],
        )
        .unwrap();

        let script = redirect.render_script();

        let occurrences = script.matches("192.168.10.254").count();
        assert_eq!(occurrences, 1);
    }
}
