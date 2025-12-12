use crate::error::DnsError;
use crate::utils::command::run_command;
use crate::Result;
use dashmap::DashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;

const NETWORK_SETUP_COMMAND: &str = "networksetup";
const DNS_GET_ARG: &str = "-getdnsservers";
const DNS_SET_ARG: &str = "-setdnsservers";
const SERVICES_GET_ARG: &str = "-listallnetworkservices";

static SERVICE_DNS_SERVERS: LazyLock<DashMap<String, Vec<IpAddr>>> = LazyLock::new(DashMap::new);

/// Gets the names of all network services on the endpoint.
///
/// ### Returns
/// A vector of network service names.
fn get_service_names() -> Result<Vec<String>> {
    // networksetup -listallnetworkservices
    let output = run_command(NETWORK_SETUP_COMMAND, [SERVICES_GET_ARG])
        .map_err(|e| DnsError::PlatformError {
            message: format!("failed to execute command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| DnsError::PlatformError {
            message: format!("failed to wait for command: {e}"),
        })?;

    if !output.status.success() {
        return Err(DnsError::PlatformError {
            message: format!(
                "failed to get network services: {}",
                String::from_utf8_lossy(&output.stdout)
            ),
        }
        .into());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let service_names = output_str
        .lines()
        .skip(1) // the first line is "An asterisk (*) denotes that a network service is disabled."
        .map(|line| line.trim().to_string())
        .collect();

    Ok(service_names)
}

/// Adds a list of DNS servers to all network services on the endpoint.
///
/// ### Arguments
/// - `dns_servers` - the DNS servers to be added
/// - `interface_name` - the name of the interface to add the DNS servers to (unused)
pub fn add_dns_servers(dns_servers: &[IpAddr], _interface_name: &str) -> Result<()> {
    let service_names = get_service_names()?;
    let dns_servers_args = dns_servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>();

    for service_name in service_names {
        // networksetup -getdnsservers <service_name>
        let get_args = [DNS_GET_ARG, &service_name];
        let get_output = run_command(NETWORK_SETUP_COMMAND, get_args)
            .map_err(|e| DnsError::PlatformError {
                message: format!("failed to execute command: {e}"),
            })?
            .wait_with_output()
            .map_err(|e| DnsError::PlatformError {
                message: format!("failed to wait for command: {e}"),
            })?;

        if !get_output.status.success() {
            return Err(DnsError::ConfigurationFailed.into());
        }

        let original_dns_servers = String::from_utf8(get_output.stdout)
            .map_err(|e| DnsError::PlatformError {
                message: format!("Failed to parse DNS servers output: {e}"),
            })?
            .lines()
            .filter_map(|dns_str| IpAddr::from_str(dns_str).ok())
            .collect();

        SERVICE_DNS_SERVERS.insert(service_name.clone(), original_dns_servers);

        // networksetup -setdnsservers <service_name> <dns_servers...>
        let set_args = [DNS_SET_ARG, &service_name].into_iter().chain(
            dns_servers_args
                .iter()
                .map(|addr_string| addr_string.as_str()),
        );

        let set_output = run_command(NETWORK_SETUP_COMMAND, set_args)
            .map_err(|e| DnsError::PlatformError {
                message: format!("failed to execute command: {e}"),
            })?
            .wait_with_output()
            .map_err(|e| DnsError::PlatformError {
                message: format!("failed to wait for command: {e}"),
            })?;

        if !set_output.status.success() {
            return Err(DnsError::ConfigurationFailed.into());
        }
    }

    Ok(())
}

/// Deletes all DNS servers from all network services on the endpoint.
pub fn delete_dns_servers() -> Result<()> {
    for service_entry in SERVICE_DNS_SERVERS.iter() {
        let service_name = service_entry.key();
        let original_dns_servers = service_entry.value();

        // If the original DNS servers are empty (set by the DHCP, ...), we need to pass "Empty"
        let dns_servers_args = if original_dns_servers.is_empty() {
            vec!["Empty".to_owned()]
        } else {
            original_dns_servers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
        };

        // networksetup -setdnsservers <service_name> <original_dns_servers...>
        let set_args = [DNS_SET_ARG, service_name].into_iter().chain(
            dns_servers_args
                .iter()
                .map(|addr_string| addr_string.as_str()),
        );

        let set_output = run_command(NETWORK_SETUP_COMMAND, set_args)
            .map_err(|e| DnsError::PlatformError {
                message: format!("failed to execute command: {e}"),
            })?
            .wait_with_output()
            .map_err(|e| DnsError::PlatformError {
                message: format!("failed to wait for command: {e}"),
            })?;

        if !set_output.status.success() {
            return Err(DnsError::RestoreFailed.into());
        }
    }

    Ok(())
}
