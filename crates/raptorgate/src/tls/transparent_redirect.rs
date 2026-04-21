use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

const TABLE_NAME: &str = "raptorgate_tls";

pub struct TransparentRedirect {
    listen_addr: SocketAddr,
    capture_interfaces: Vec<String>,
    inspection_ports: Vec<u16>,
}

impl TransparentRedirect {
    pub fn new(
        listen_addr: SocketAddr,
        capture_interfaces: Vec<String>,
        inspection_ports: Vec<u16>,
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

        Ok(Self {
            listen_addr,
            capture_interfaces,
            inspection_ports,
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

        format!(
            "table inet {table_name} {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        iifname {{ {interfaces} }} tcp dport {{ {ports} }} redirect to :{listen_port}
    }}
}}
",
            table_name = TABLE_NAME,
            interfaces = interfaces,
            ports = ports,
            listen_port = self.listen_addr.port()
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
        );
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_empty_inspection_ports() {
        let result = TransparentRedirect::new(
            "127.0.0.1:8443".parse().unwrap(),
            vec!["eth1".into()],
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
        )
        .unwrap();

        let script = redirect.render_script();

        assert!(script.contains("tcp dport { 443, 993, 8443 }"));
    }
}
