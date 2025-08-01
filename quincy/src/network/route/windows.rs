use crate::utils::command::run_command;
use anyhow::{anyhow, Result};
use ipnet::IpNet;
use std::net::IpAddr;

const NETSH_ROUTE_ADD_COMMAND: &str =
    "netsh interface ip add route {network} \"{interface_name}\" {gateway} store=active";

/// Adds a list of routes to the routing table.
///
/// ### Arguments
/// - `networks` - the networks to be routed through the gateway
/// - `gateway` - the gateway to be used for the routes
/// - `interface_name` - the name of the interface to add the routes to
pub fn add_routes(networks: &[IpNet], gateway: &IpAddr, interface_name: &str) -> Result<()> {
    for network in networks {
        add_route(network, gateway, interface_name)?;
    }

    Ok(())
}

/// Adds a route to the routing table.
///
/// ### Arguments
/// - `network` - the network to be routed through the gateway
/// - `gateway` - the gateway to be used for the route
/// - `interface_name` - the name of the interface to add the route to
fn add_route(network: &IpNet, gateway: &IpAddr, interface_name: &str) -> Result<()> {
    let route_add_command = NETSH_ROUTE_ADD_COMMAND
        .replace("{network}", &network.to_string())
        .replace("{interface_name}", interface_name)
        .replace("{gateway}", &gateway.to_string());

    let route_command_split = route_add_command.split(" ").collect::<Vec<_>>();

    let route_program = route_command_split[0];
    let route_args = &route_command_split[1..];

    let output = run_command(route_program, route_args)?.wait_with_output()?;

    if !output.status.success() {
        return Err(anyhow!(
            "failed to add route: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}
