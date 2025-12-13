use crate::error::RouteError;
use crate::utils::command::run_command;
use crate::Result;
use ipnet::IpNet;
use std::net::IpAddr;

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
    let network_str = network.to_string();
    let gateway_str = gateway.to_string();
    let route_args = vec![
        "interface",
        "ip",
        "add",
        "route",
        &network_str,
        interface_name,
        &gateway_str,
        "store=active",
    ];

    let output = run_command("netsh", &route_args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for command: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RouteError::AddFailed {
            destination: network.to_string(),
            message: stderr.trim().to_string(),
        }
        .into());
    }

    Ok(())
}
