use crate::utils::command::run_command;
use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
const ROUTE_ADD_COMMAND: &str = "route add -net {network} netmask {netmask} gw {gateway}";
#[cfg(target_os = "macos")]
const ROUTE_ADD_COMMAND: &str = "route -n add -net {network} -netmask {netmask} {gateway}";
#[cfg(target_os = "freebsd")]
const ROUTE_ADD_COMMAND: &str = "route add -net {network} -netmask {netmask} {gateway}";

/// Adds a list of routes to the routing table.
///
/// ### Arguments
/// - `networks` - the networks to be routed through the gateway
/// - `gateway` - the gateway to be used for the routes
/// - `_interface_name` - the name of the interface to add the routes to (ignored on Unix systems)
pub fn add_routes(networks: &[IpNet], gateway: &IpAddr, _interface_name: &str) -> Result<()> {
    for network in networks {
        add_route(network, gateway)?;
    }

    Ok(())
}

/// Adds a route to the routing table.
///
/// ### Arguments
/// - `network` - the network to be routed through the gateway
/// - `gateway` - the gateway to be used for the route
fn add_route(network: &IpNet, gateway: &IpAddr) -> Result<()> {
    let route_add_command = ROUTE_ADD_COMMAND
        .replace("{network}", &network.addr().to_string())
        .replace("{netmask}", &network.netmask().to_string())
        .replace("{gateway}", &gateway.to_string());

    let route_command_split = route_add_command.split(" ").collect::<Vec<_>>();

    let route_program = route_command_split[0];
    let route_args = &route_command_split[1..];

    let output = run_command(route_program, route_args)?
        .wait_with_output()
        .context("failed to create child process")?;

    if !output.status.success() {
        return Err(anyhow!(
            "failed to add route: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}
