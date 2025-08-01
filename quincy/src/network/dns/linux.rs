use crate::utils::command::run_command;
use anyhow::{anyhow, Context, Result};
use std::io::Write;
use std::net::IpAddr;

const RESOLVCONF_COMMAND: &str = "resolvconf";

/// Adds a list of DNS servers to the given interface.
///
/// ### Arguments
/// - `dns_servers` - the DNS servers to be added
/// - `interface_name` - the name of the interface to add the DNS servers to
pub fn add_dns_servers(dns_servers: &[IpAddr], interface_name: &str) -> Result<()> {
    let set_args = ["-a", interface_name, "-x"];
    let input = dns_servers
        .iter()
        .map(|ip| format!("nameserver {ip}"))
        .collect::<Vec<_>>()
        .join("\n");

    let mut process = run_command(RESOLVCONF_COMMAND, set_args)?;

    if let Some(mut stdin) = process.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .context("failed to write to stdin")?;
    } else {
        return Err(anyhow!("failed to open stdin"));
    }

    let output = process
        .wait_with_output()
        .context("failed to wait for process to exit")?;

    if !output.status.success() {
        let error_message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(anyhow!(error_message));
    }

    Ok(())
}

/// Deletes all DNS servers from the given interface.
///
/// No-op on Linux/FreeBSD.
pub fn delete_dns_servers() -> Result<()> {
    // This is a no-op on Linux and FreeBSD as the interface is deleted when the process exits
    // along with its routes and DNS servers
    Ok(())
}
