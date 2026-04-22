use crate::error::RouteError;
use crate::network::route::{InstalledExclusionRoute, NextHop};
use crate::utils::command::run_command;
use crate::Result;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Output;
use std::str::FromStr;
use tracing::warn;

/// Absolute path to the Linux `ip` utility.
///
/// Hard-coded to avoid `PATH`-based resolution: the callers run as root
/// during route installation and must not be influenced by a caller-supplied
/// or inherited `PATH`.  `/sbin/ip` is the canonical iproute2 location on
/// every supported distribution; on systems that have merged `/sbin` into
/// `/usr/sbin`, `/sbin` is a symlink and the path resolves transparently.
#[cfg(target_os = "linux")]
const IP_COMMAND: &str = "/sbin/ip";

/// Absolute path to the `route` utility.
///
/// Hard-coded to avoid `PATH`-based resolution.  `/sbin/route` is the
/// canonical location on Linux (net-tools), macOS, and FreeBSD.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
const ROUTE_COMMAND: &str = "/sbin/route";

/// Adds a list of routes to the routing table, optionally installing an
/// exclusion host-route for the VPN server first.
///
/// When `remote_address` is `Some(addr)`, the function looks up the current
/// next-hop for `addr` and installs a pinning host-route before adding any
/// user routes.  On macOS/FreeBSD, exact default routes (`0.0.0.0/0` and
/// `::/0`) are split into two halves (`/1` pairs) before both the coverage
/// check and route installation, matching BSD kernel behaviour.
///
/// If the exclusion route cannot be installed **and** the (post-split) user
/// routes would cover `remote_address`, a hard
/// [`RouteError::ExclusionRequired`] error is returned.  If the routes do
/// **not** cover the server, the function logs a warning and continues
/// without the exclusion route.
///
/// If a later user-route addition fails after the exclusion route was
/// successfully installed, the exclusion route is removed before the
/// original error is returned.
///
/// ### Arguments
/// - `networks` - the networks to be routed through the gateway
/// - `gateway` - the gateway to be used for the routes
/// - `tunnel_interface` - the name of the tunnel interface being configured;
///   used to reject exclusion next-hops that resolve through the tunnel itself
/// - `remote_address` - optional VPN server address requiring an exclusion route
pub fn add_routes(
    networks: &[IpNet],
    gateway: &IpAddr,
    tunnel_interface: &str,
    remote_address: Option<IpAddr>,
) -> Result<Option<InstalledExclusionRoute>> {
    // On BSD, split exact default routes before coverage checks and route
    // installation so the kernel sees /1 pairs instead of /0.
    let split_networks;
    let effective_networks = if cfg!(any(target_os = "macos", target_os = "freebsd")) {
        split_networks = bsd_split_default_routes(networks);
        &split_networks
    } else {
        networks
    };

    let exclusion = match remote_address {
        Some(server) => match install_exclusion_for_server(&server, tunnel_interface) {
            // `Some(token)` means Quincy installed the route and owns teardown;
            // `None` means an equivalent route was already present and is fine
            // to rely on, but we do not claim teardown ownership for it.
            Ok(token) => token,
            Err(err) => {
                if any_route_covers_address(effective_networks, &server) {
                    return Err(RouteError::ExclusionRequired { server }.into());
                }
                warn!(
                    %server,
                    "exclusion route could not be installed but routes do not \
                     cover the server; continuing: {err}"
                );
                None
            }
        },
        None => None,
    };

    for network in effective_networks {
        if let Err(add_err) = add_route(network, gateway) {
            if let Some(ref token) = exclusion {
                if let Err(rm_err) = remove_exclusion_route(token) {
                    warn!(
                        "failed to roll back exclusion route for {}: {rm_err}",
                        token.destination
                    );
                }
            }
            return Err(add_err);
        }
    }

    Ok(exclusion)
}

/// Attempts to discover the current next-hop for `server` and install an
/// exclusion host-route via that next-hop.
///
/// Rejects next-hops whose egress interface is the tunnel interface itself:
/// such a route would forward the server's control-plane traffic back into
/// the VPN, defeating the exclusion and creating a routing loop.  This can
/// happen if `add_routes` is invoked after the tunnel has already captured
/// the relevant portion of the routing table.
fn install_exclusion_for_server(
    server: &IpAddr,
    tunnel_interface: &str,
) -> Result<Option<InstalledExclusionRoute>> {
    let next_hop = get_route_to(server)?;

    if next_hop_uses_interface(&next_hop, tunnel_interface) {
        return Err(RouteError::PlatformError {
            message: format!(
                "refusing to install exclusion route for {server}: resolved next-hop \
                 egress interface '{tunnel_interface}' is the tunnel itself"
            ),
        }
        .into());
    }

    add_exclusion_route(server, &next_hop)
}

/// Returns `true` when `next_hop` egresses via `interface`.
///
/// The match is exact (case-sensitive) because OS interface names are
/// case-sensitive on Linux, macOS, and FreeBSD.  An empty `interface`
/// argument disables the check.
fn next_hop_uses_interface(next_hop: &NextHop, interface: &str) -> bool {
    if interface.is_empty() {
        return false;
    }
    let hop_iface = match next_hop {
        NextHop::Gateway { interface, .. } | NextHop::OnLink { interface } => interface.as_str(),
    };
    hop_iface == interface
}

/// On macOS and FreeBSD the kernel rejects exact `/0` default routes added
/// alongside a tunnel interface.  This helper replaces each `/0` with a pair
/// of `/1` routes that together cover the full address space:
///
/// - `0.0.0.0/0`  → `0.0.0.0/1` + `128.0.0.0/1`
/// - `::/0`       → `::/1`      + `8000::/1`
///
/// Non-default routes are passed through unchanged.
pub(crate) fn bsd_split_default_routes(networks: &[IpNet]) -> Vec<IpNet> {
    let mut out = Vec::with_capacity(networks.len());
    for net in networks {
        match net {
            IpNet::V4(v4) if v4.prefix_len() == 0 => {
                // 0.0.0.0/1
                out.push(IpNet::V4(
                    Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 1).unwrap(),
                ));
                // 128.0.0.0/1
                out.push(IpNet::V4(
                    Ipv4Net::new(Ipv4Addr::new(128, 0, 0, 0), 1).unwrap(),
                ));
            }
            IpNet::V6(v6) if v6.prefix_len() == 0 => {
                // ::/1
                out.push(IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 1).unwrap()));
                // 8000::/1
                out.push(IpNet::V6(
                    Ipv6Net::new(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1).unwrap(),
                ));
            }
            other => out.push(*other),
        }
    }
    out
}

pub(crate) fn any_route_covers_address(routes: &[IpNet], address: &IpAddr) -> bool {
    routes.iter().any(|net| net.contains(address))
}

fn add_route(network: &IpNet, gateway: &IpAddr) -> Result<()> {
    let args = user_route_add_args(network, gateway);
    let program = &args[0];
    let cmd_args = &args[1..];

    let output = run_command(program, cmd_args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to create child process: {e}"),
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

/// Builds the argv for a user-route add command.
///
/// Emitting a `Vec<String>` directly keeps numeric/stringy arguments intact
/// (no tokenization accidents when an address happens to contain a space-
/// like separator in future formats) and makes the per-platform layout
/// immediately auditable at the call site.
#[cfg(target_os = "linux")]
fn user_route_add_args(network: &IpNet, gateway: &IpAddr) -> Vec<String> {
    match network {
        IpNet::V4(_) => vec![
            ROUTE_COMMAND.to_string(),
            "add".to_string(),
            "-net".to_string(),
            network.addr().to_string(),
            "netmask".to_string(),
            network.netmask().to_string(),
            "gw".to_string(),
            gateway.to_string(),
        ],
        IpNet::V6(_) => vec![
            ROUTE_COMMAND.to_string(),
            "-A".to_string(),
            "inet6".to_string(),
            "add".to_string(),
            format!("{}/{}", network.addr(), network.prefix_len()),
            "gw".to_string(),
            gateway.to_string(),
        ],
    }
}

/// Builds the argv for a user-route add command on macOS.
#[cfg(target_os = "macos")]
fn user_route_add_args(network: &IpNet, gateway: &IpAddr) -> Vec<String> {
    match network {
        IpNet::V4(_) => vec![
            ROUTE_COMMAND.to_string(),
            "-n".to_string(),
            "add".to_string(),
            "-net".to_string(),
            network.addr().to_string(),
            "-netmask".to_string(),
            network.netmask().to_string(),
            gateway.to_string(),
        ],
        IpNet::V6(_) => vec![
            ROUTE_COMMAND.to_string(),
            "-n".to_string(),
            "add".to_string(),
            "-inet6".to_string(),
            format!("{}/{}", network.addr(), network.prefix_len()),
            gateway.to_string(),
        ],
    }
}

/// Builds the argv for a user-route add command on FreeBSD.
#[cfg(target_os = "freebsd")]
fn user_route_add_args(network: &IpNet, gateway: &IpAddr) -> Vec<String> {
    match network {
        IpNet::V4(_) => vec![
            ROUTE_COMMAND.to_string(),
            "add".to_string(),
            "-net".to_string(),
            network.addr().to_string(),
            "-netmask".to_string(),
            network.netmask().to_string(),
            gateway.to_string(),
        ],
        IpNet::V6(_) => vec![
            ROUTE_COMMAND.to_string(),
            "add".to_string(),
            "-inet6".to_string(),
            format!("{}/{}", network.addr(), network.prefix_len()),
            gateway.to_string(),
        ],
    }
}

/// Queries the system routing table for the next hop to reach `address`.
///
/// Runs `ip route get` on Linux or `route -n get` on macOS/FreeBSD, then
/// delegates to the appropriate platform-specific parser.
pub fn get_route_to(address: &IpAddr) -> Result<NextHop> {
    let output = run_route_get_command(address)?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    #[cfg(target_os = "linux")]
    {
        parse_linux_route_get(&stdout, address)
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        parse_bsd_route_get(&stdout, address)
    }
}

/// Installs a host route (`/32` for IPv4, `/128` for IPv6) that pins traffic
/// for `server` to the given `next_hop`, preventing the VPN tunnel from
/// capturing its own control-plane traffic.
///
/// Returns `Ok(Some(token))` when Quincy actually installed the route, so
/// cleanup can remove it later.  Returns `Ok(None)` when an equivalent
/// route was already present in the OS table: the route is fine to use,
/// but we did not install it and therefore must not take ownership of
/// removing it.
///
/// Duplicate detection does not rely on a non-zero exit status or on any
/// particular output stream: some platforms print `File exists` /
/// `route already in table` to stdout with a zero exit code.  Both streams
/// are inspected, and when a duplicate marker is found we re-query the
/// kernel to decide whether the pre-existing route's next-hop matches.
/// A mismatching next-hop is still an error, so cleanup never touches a
/// route owned by another process or configuration.
pub fn add_exclusion_route(
    server: &IpAddr,
    next_hop: &NextHop,
) -> Result<Option<InstalledExclusionRoute>> {
    let args = exclusion_route_cmd_args(server, next_hop, ExclusionAction::Add);
    let program = &args[0];
    let cmd_args = &args[1..];

    let output = run_command(program, cmd_args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute exclusion route add command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for exclusion route add command: {e}"),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let already_exists =
        output_indicates_already_exists(&stdout) || output_indicates_already_exists(&stderr);

    if !output.status.success() && !already_exists {
        return Err(RouteError::AddFailed {
            destination: server.to_string(),
            message: stderr.trim().to_string(),
        }
        .into());
    }

    if already_exists {
        // A route for this destination already existed before we ran.
        // Verify its next-hop matches what we intended to install so we
        // neither adopt a foreign route nor silently route server traffic
        // somewhere unexpected.
        let existing = get_route_to(server).map_err(|e| RouteError::AddFailed {
            destination: server.to_string(),
            message: format!(
                "exclusion route already exists but re-query failed, \
                 refusing to adopt foreign route: {e}"
            ),
        })?;

        if existing != *next_hop {
            return Err(RouteError::AddFailed {
                destination: server.to_string(),
                message: format!(
                    "exclusion route already exists with a different next-hop \
                     ({existing:?}) than the one we tried to install ({next_hop:?}); \
                     refusing to adopt foreign route"
                ),
            }
            .into());
        }

        // Pre-existing equivalent route: treat as success but do not mint a
        // teardown token, since Quincy did not install it.
        return Ok(None);
    }

    Ok(Some(InstalledExclusionRoute {
        destination: *server,
        next_hop: next_hop.clone(),
    }))
}

/// Removes a previously installed exclusion host route.
///
/// The initial delete is issued against the exact next-hop that was stored
/// in the token.  If the kernel rejects it (typically because the gateway
/// has changed since installation, e.g. after a DHCP lease renewal or
/// network roaming), we retry once with a destination-plus-interface
/// command that the kernel can match regardless of the current gateway.
/// The fallback remains scoped to the installed interface so we do not
/// accidentally delete a same-destination route on an unrelated interface
/// that appeared after the original install.
///
/// An "already absent" response on either attempt is treated as success:
/// the desired end state (no exclusion route) is already in place, and
/// cleanup is best-effort.
pub fn remove_exclusion_route(exclusion: &InstalledExclusionRoute) -> Result<()> {
    let args = exclusion_route_cmd_args(
        &exclusion.destination,
        &exclusion.next_hop,
        ExclusionAction::Remove,
    );
    let output = run_exclusion_remove(&args)?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output_indicates_not_found(&stdout) || output_indicates_not_found(&stderr) {
        return Ok(());
    }

    let destination = exclusion.destination;
    warn!(
        %destination,
        "exclusion route removal with stored next-hop failed ({}); retrying \
         with destination+interface command",
        stderr.trim()
    );

    let fallback_args =
        exclusion_route_remove_fallback_args(&exclusion.next_hop, &exclusion.destination);
    let fallback_output = run_exclusion_remove(&fallback_args)?;

    if fallback_output.status.success() {
        return Ok(());
    }

    let fb_stdout = String::from_utf8_lossy(&fallback_output.stdout);
    let fb_stderr = String::from_utf8_lossy(&fallback_output.stderr);

    if output_indicates_not_found(&fb_stdout) || output_indicates_not_found(&fb_stderr) {
        return Ok(());
    }

    Err(RouteError::RemoveFailed {
        destination: exclusion.destination.to_string(),
    }
    .into())
}

/// Runs a pre-built exclusion-route remove command, surfacing spawn/wait
/// failures as [`RouteError::PlatformError`].  A non-zero exit status is
/// reported via the returned [`Output`] so callers can inspect stderr and
/// decide whether to retry.
fn run_exclusion_remove(args: &[String]) -> Result<Output> {
    let program = &args[0];
    let cmd_args = &args[1..];

    let output = run_command(program, cmd_args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute exclusion route remove command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for exclusion route remove command: {e}"),
        })?;

    Ok(output)
}

/// Returns the egress interface of a next-hop.
fn next_hop_interface(next_hop: &NextHop) -> &str {
    match next_hop {
        NextHop::Gateway { interface, .. } | NextHop::OnLink { interface } => interface,
    }
}

/// Builds a destination + interface remove command used when the original
/// next-hop's gateway no longer matches the installed route (e.g., after a
/// DHCP renewal or roaming event).  The kernel resolves the route by its
/// destination prefix, but we keep the egress interface attached so a
/// later-appearing same-destination route on a different interface is not
/// deleted by mistake.
#[cfg(target_os = "linux")]
fn exclusion_route_remove_fallback_args(next_hop: &NextHop, server: &IpAddr) -> Vec<String> {
    let host_cidr = match server {
        IpAddr::V4(v4) => format!("{v4}/32"),
        IpAddr::V6(v6) => format!("{v6}/128"),
    };

    let mut args = vec![IP_COMMAND.to_string()];
    if server.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend(["route".to_string(), "delete".to_string(), host_cidr]);
    args.extend(["dev".to_string(), next_hop_interface(next_hop).to_string()]);
    args
}

/// BSD variant of [`exclusion_route_remove_fallback_args`].  `route -n
/// delete -host <addr> -ifp <iface>` matches the installed host route by
/// destination and interface without requiring the original gateway.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn exclusion_route_remove_fallback_args(next_hop: &NextHop, server: &IpAddr) -> Vec<String> {
    let mut args = vec![
        ROUTE_COMMAND.to_string(),
        "-n".to_string(),
        "delete".to_string(),
    ];
    if server.is_ipv6() {
        args.push("-inet6".to_string());
    }
    args.extend(["-host".to_string(), server.to_string()]);
    args.extend(["-ifp".to_string(), next_hop_interface(next_hop).to_string()]);
    args
}

#[derive(Clone, Copy)]
enum ExclusionAction {
    Add,
    Remove,
}

/// Shared builder for exclusion-route add/remove commands.
#[cfg(target_os = "linux")]
fn exclusion_route_cmd_args(
    server: &IpAddr,
    next_hop: &NextHop,
    action: ExclusionAction,
) -> Vec<String> {
    let action_str = match action {
        ExclusionAction::Add => "add",
        ExclusionAction::Remove => "delete",
    };
    let host_cidr = match server {
        IpAddr::V4(v4) => format!("{v4}/32"),
        IpAddr::V6(v6) => format!("{v6}/128"),
    };

    let mut args = vec![IP_COMMAND.to_string()];
    if server.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend(["route".to_string(), action_str.to_string(), host_cidr]);

    match next_hop {
        NextHop::Gateway { address, interface } => {
            args.extend(["via".to_string(), address.to_string()]);
            // Link-local gateways (IPv4 169.254.0.0/16, IPv6 fe80::/10) are
            // ambiguous on multi-homed hosts without explicit interface
            // context, so pin them to the discovered interface.
            if is_link_local(address) {
                args.extend(["dev".to_string(), interface.clone()]);
            }
        }
        NextHop::OnLink { interface } => {
            args.extend(["dev".to_string(), interface.clone()]);
        }
    }

    args
}

/// Shared builder for exclusion-route add/remove commands.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn exclusion_route_cmd_args(
    server: &IpAddr,
    next_hop: &NextHop,
    action: ExclusionAction,
) -> Vec<String> {
    let action_str = match action {
        ExclusionAction::Add => "add",
        ExclusionAction::Remove => "delete",
    };

    let mut args = vec![
        ROUTE_COMMAND.to_string(),
        "-n".to_string(),
        action_str.to_string(),
    ];
    if server.is_ipv6() {
        args.push("-inet6".to_string());
    }
    args.extend(["-host".to_string(), server.to_string()]);

    match next_hop {
        NextHop::Gateway { address, interface } => {
            // Link-local IPv6 gateways require the scoped form `addr%iface`
            // so the BSD kernel can resolve the on-link neighbour.
            if is_ipv6_link_local(address) {
                args.push(format!("{address}%{interface}"));
            } else {
                args.push(address.to_string());
            }
        }
        NextHop::OnLink { interface } => {
            args.extend(["-interface".to_string(), interface.clone()]);
        }
    }

    args
}

/// Returns `true` when the address is an IPv6 link-local address (`fe80::/10`).
///
/// Uses a manual prefix check to stay compatible with MSRV 1.80 (the std
/// method `Ipv6Addr::is_unicast_link_local` stabilised in 1.84).
fn is_ipv6_link_local(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
        IpAddr::V4(_) => false,
    }
}

/// Returns `true` when the address is an IPv4 link-local (`169.254.0.0/16`)
/// or IPv6 link-local (`fe80::/10`) address.
///
/// On multi-homed hosts, link-local next-hops are ambiguous without an
/// explicit interface, so callers must pair the gateway with `dev <iface>`
/// (Linux) or a scoped form (BSD IPv6 only).
#[cfg(target_os = "linux")]
fn is_link_local(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(_) => is_ipv6_link_local(addr),
    }
}

/// Returns `true` when output from a route-add command indicates the route
/// already exists.
///
/// Linux emits `RTNETLINK answers: File exists`, while macOS/FreeBSD emit
/// messages containing `File exists` or `route already in table`.  Callers
/// must check both stdout and stderr: the `route` utility on BSD variants
/// can print the duplicate marker to stdout with a zero exit status, and
/// `ip` has been observed to do the same under certain error-reporting
/// flags.  `LC_ALL=C` is applied at spawn time (`utils::command::run_command`)
/// so this match is not defeated by localized translations.
fn output_indicates_already_exists(output: &str) -> bool {
    let lower = output.to_lowercase();
    lower.contains("file exists") || lower.contains("route already in table")
}

/// Returns `true` when output from a route-delete command indicates the
/// route was already absent.
///
/// Treating "already absent" as success makes removal idempotent: if the
/// kernel dropped the route between installation and teardown (roaming,
/// DHCP renew, manual intervention) the cleanup path should not surface
/// a hard error.  Matches Linux (`RTNETLINK answers: No such process`,
/// `Cannot find`) and BSD (`not in table`, `no such process`,
/// `no such file or directory`).
fn output_indicates_not_found(output: &str) -> bool {
    let lower = output.to_lowercase();
    lower.contains("no such process")
        || lower.contains("not in table")
        || lower.contains("cannot find")
        || lower.contains("no such file or directory")
}

fn run_route_get_command(address: &IpAddr) -> Result<Output> {
    let addr_str = address.to_string();

    #[cfg(target_os = "linux")]
    let (program, args): (&str, Vec<&str>) = match address {
        IpAddr::V4(_) => (IP_COMMAND, vec!["route", "get", &addr_str]),
        IpAddr::V6(_) => (IP_COMMAND, vec!["-6", "route", "get", &addr_str]),
    };

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    let (program, args): (&str, Vec<&str>) = match address {
        IpAddr::V4(_) => (ROUTE_COMMAND, vec!["-n", "get", &addr_str]),
        IpAddr::V6(_) => (ROUTE_COMMAND, vec!["-n", "get", "-inet6", &addr_str]),
    };

    let output = run_command(program, &args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute route-get command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for route-get command: {e}"),
        })?;

    if !output.status.success() {
        return Err(RouteError::NotFound {
            destination: address.to_string(),
        }
        .into());
    }

    Ok(output)
}

/// Parses the output of `ip route get <addr>` on Linux.
///
/// Example IPv4 output:
/// ```text
/// 8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 1000
/// ```
///
/// Example IPv4 on-link output:
/// ```text
/// 192.168.1.5 dev eth0 src 192.168.1.100 uid 1000
/// ```
///
/// Example IPv6 output:
/// ```text
/// 2001:4860:4860::8888 from :: via fe80::1 dev eth0 proto ra src 2001:db8::1 metric 100 pref medium
/// ```
#[cfg(target_os = "linux")]
fn parse_linux_route_get(output: &str, address: &IpAddr) -> Result<NextHop> {
    // Join continuation lines (lines starting with whitespace) into a single
    // logical line.  Only the *first* non-continuation block is kept so that
    // unusual multipath output cannot mix gateway and interface from different
    // route entries.
    let joined = output
        .lines()
        .filter(|l| !l.is_empty())
        .fold((String::new(), false), |(mut acc, done), line| {
            if done {
                return (acc, true);
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                acc.push(' ');
                acc.push_str(line.trim());
            } else {
                if !acc.is_empty() {
                    // Second non-continuation line, stop.
                    return (acc, true);
                }
                acc.push_str(line.trim());
            }
            (acc, false)
        })
        .0;

    let tokens: Vec<&str> = joined.split_whitespace().collect();

    // Reject special route types that cannot be used as an exclusion
    // next-hop.  `ip route get` prefixes the destination with the route
    // type keyword (e.g. `unreachable 10.0.0.1 dev lo ...`).  An exclusion
    // route installed via an unreachable/blackhole/prohibit/throw route
    // would either drop the server's traffic or fall through to a later
    // lookup that may now be captured by the tunnel, so we refuse outright.
    if let Some(first) = tokens.first() {
        if matches!(*first, "unreachable" | "blackhole" | "prohibit" | "throw") {
            return Err(RouteError::NotFound {
                destination: address.to_string(),
            }
            .into());
        }
    }

    let interface = find_token_value(&tokens, "dev")
        .map(String::from)
        .ok_or_else(|| RouteError::PlatformError {
            message: format!(
                "could not determine interface from route output for {address}: {output}"
            ),
        })?;

    // Strip scope-id (e.g. `%eth0`) from the gateway token before parsing,
    // since Rust's `IpAddr` does not accept scope identifiers.  An
    // unparsable `via` token is a hard error: falling back to on-link
    // here would silently replace a misconfigured/strange gateway with a
    // host route that forwards the server's traffic onto the current
    // interface, which could easily be the tunnel itself.
    let gateway = match find_token_value(&tokens, "via") {
        Some(raw) => {
            let without_scope = raw.split('%').next().unwrap_or(raw);
            let parsed =
                IpAddr::from_str(without_scope).map_err(|_| RouteError::PlatformError {
                    message: format!(
                        "could not parse gateway '{raw}' from route output for {address}: {output}"
                    ),
                })?;
            Some(parsed)
        }
        None => None,
    };

    match gateway {
        Some(addr) => Ok(NextHop::Gateway {
            address: addr,
            interface,
        }),
        None => Ok(NextHop::OnLink { interface }),
    }
}

/// Parses the output of `route -n get <addr>` on macOS and FreeBSD.
///
/// Example IPv4 output:
/// ```text
///    route to: 8.8.8.8
/// destination: default
///        mask: default
///     gateway: 192.168.1.1
///   interface: en0
/// ```
///
/// Example IPv4 on-link output:
/// ```text
///    route to: 192.168.1.5
/// destination: 192.168.1.0
///        mask: 255.255.255.0
///   interface: en0
/// ```
///
/// Example IPv6 output:
/// ```text
///    route to: 2001:4860:4860::8888
/// destination: default
///     gateway: fe80::1%en0
///   interface: en0
/// ```
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn parse_bsd_route_get(output: &str, address: &IpAddr) -> Result<NextHop> {
    let mut gateway: Option<IpAddr> = None;
    let mut interface: Option<String> = None;

    for line in output.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("gateway:") {
            let raw = value.trim();
            // BSD may append a scope-id like "%en0" to link-local IPv6 addresses;
            // strip it before parsing.
            let without_scope = raw.split('%').next().unwrap_or(raw);
            // Treat unspecified addresses (0.0.0.0 / ::) as on-link; FreeBSD
            // emits these for directly-reachable destinations.
            let parsed = IpAddr::from_str(without_scope)
                .ok()
                .filter(|addr| !addr.is_unspecified());
            // Only update if we got a valid parse; avoid overwriting a
            // previously valid gateway with None from a later unparsable
            // line.
            if parsed.is_some() {
                gateway = parsed;
            }
        } else if let Some(value) = line.strip_prefix("interface:") {
            interface = Some(value.trim().to_string());
        }
    }

    let interface = interface.ok_or_else(|| RouteError::PlatformError {
        message: format!("could not determine interface from route output for {address}: {output}"),
    })?;

    match gateway {
        Some(addr) => Ok(NextHop::Gateway {
            address: addr,
            interface,
        }),
        None => Ok(NextHop::OnLink { interface }),
    }
}

#[cfg(target_os = "linux")]
fn find_token_value<'a>(tokens: &[&'a str], key: &str) -> Option<&'a str> {
    tokens
        .windows(2)
        .find(|pair| pair[0] == key)
        .map(|pair| pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[cfg(target_os = "linux")]
    mod linux_parser {
        use super::*;

        #[test]
        fn ipv4_gateway() {
            let output = "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 1000\n    cache\n";
            let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            let hop = parse_linux_route_get(output, &addr).unwrap();

            match hop {
                NextHop::Gateway { address, interface } => {
                    assert_eq!(address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                    assert_eq!(interface, "eth0");
                }
                _ => panic!("expected Gateway, got {hop:?}"),
            }
        }

        #[test]
        fn ipv4_onlink() {
            let output = "192.168.1.5 dev eth0 src 192.168.1.100 uid 1000\n    cache\n";
            let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
            let hop = parse_linux_route_get(output, &addr).unwrap();

            match hop {
                NextHop::OnLink { interface } => {
                    assert_eq!(interface, "eth0");
                }
                _ => panic!("expected OnLink, got {hop:?}"),
            }
        }

        #[test]
        fn ipv4_multiline() {
            // Some kernels split the output across multiple lines
            let output = "\
8.8.8.8 via 10.0.0.1 dev wlan0
    src 10.0.0.42 uid 1000
    cache
";
            let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            let hop = parse_linux_route_get(output, &addr).unwrap();

            match hop {
                NextHop::Gateway { address, interface } => {
                    assert_eq!(address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                    assert_eq!(interface, "wlan0");
                }
                _ => panic!("expected Gateway, got {hop:?}"),
            }
        }

        #[test]
        fn ipv6_gateway() {
            let output = "2001:4860:4860::8888 from :: via fe80::1 dev eth0 proto ra src 2001:db8::1 metric 100 pref medium\n";
            let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
            let hop = parse_linux_route_get(output, &addr).unwrap();

            match hop {
                NextHop::Gateway { address, interface } => {
                    assert_eq!(
                        address,
                        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
                    );
                    assert_eq!(interface, "eth0");
                }
                _ => panic!("expected Gateway, got {hop:?}"),
            }
        }

        #[test]
        fn ipv6_onlink() {
            let output = "fe80::5 dev eth0 src fe80::1 metric 0 pref medium\n";
            let addr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5));
            let hop = parse_linux_route_get(output, &addr).unwrap();

            match hop {
                NextHop::OnLink { interface } => {
                    assert_eq!(interface, "eth0");
                }
                _ => panic!("expected OnLink, got {hop:?}"),
            }
        }

        #[test]
        fn ipv6_scoped_gateway_stripped() {
            // Linux can emit `via fe80::1%eth0`; Rust's IpAddr doesn't parse
            // scope IDs, so the parser must strip the `%eth0` suffix.
            let output = "2001:db8::1 from :: via fe80::1%eth0 dev eth0 proto ra src 2001:db8::2 metric 100 pref medium\n";
            let addr: IpAddr = "2001:db8::1".parse().unwrap();
            let hop = parse_linux_route_get(output, &addr).unwrap();

            match hop {
                NextHop::Gateway { address, interface } => {
                    assert_eq!(
                        address,
                        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
                    );
                    assert_eq!(interface, "eth0");
                }
                _ => panic!("expected Gateway, got {hop:?}"),
            }
        }

        #[test]
        fn unparsable_gateway_returns_error() {
            // If the gateway token is completely unparsable even after scope
            // stripping, the parser must surface a hard error rather than
            // silently downgrading to on-link: downgrading would point the
            // host-route at the current `dev` (potentially the tunnel
            // itself) and defeat the exclusion.
            let output = "10.0.0.1 via link#5 dev eth0 src 10.0.0.2\n";
            let addr: IpAddr = "10.0.0.1".parse().unwrap();
            let err = parse_linux_route_get(output, &addr).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("could not parse gateway"),
                "expected parse error, got: {msg}"
            );
        }

        #[test]
        fn unreachable_is_rejected() {
            let output = "unreachable 10.0.0.1 dev lo table main src 1.2.3.4 uid 1000\n    cache\n";
            let addr: IpAddr = "10.0.0.1".parse().unwrap();
            let err = parse_linux_route_get(output, &addr).unwrap_err();
            assert!(
                matches!(
                    err,
                    crate::error::QuincyError::Route(RouteError::NotFound { .. })
                ),
                "expected RouteError::NotFound, got: {err}"
            );
        }

        #[test]
        fn blackhole_is_rejected() {
            let output = "blackhole 10.0.0.1\n    cache\n";
            let addr: IpAddr = "10.0.0.1".parse().unwrap();
            let err = parse_linux_route_get(output, &addr).unwrap_err();
            assert!(
                matches!(
                    err,
                    crate::error::QuincyError::Route(RouteError::NotFound { .. })
                ),
                "expected RouteError::NotFound, got: {err}"
            );
        }

        #[test]
        fn prohibit_is_rejected() {
            let output = "prohibit 10.0.0.1 dev lo table main src 1.2.3.4 uid 1000\n";
            let addr: IpAddr = "10.0.0.1".parse().unwrap();
            let err = parse_linux_route_get(output, &addr).unwrap_err();
            assert!(
                matches!(
                    err,
                    crate::error::QuincyError::Route(RouteError::NotFound { .. })
                ),
                "expected RouteError::NotFound, got: {err}"
            );
        }

        #[test]
        fn throw_is_rejected() {
            let output = "throw 10.0.0.1\n    cache\n";
            let addr: IpAddr = "10.0.0.1".parse().unwrap();
            let err = parse_linux_route_get(output, &addr).unwrap_err();
            assert!(
                matches!(
                    err,
                    crate::error::QuincyError::Route(RouteError::NotFound { .. })
                ),
                "expected RouteError::NotFound, got: {err}"
            );
        }

        #[test]
        fn multiblock_uses_only_first_block() {
            // If `ip route get` emits two non-continuation lines, only the
            // first block's gateway and interface should be used.
            let output = "\
8.8.8.8 via 10.0.0.1 dev wlan0
    src 10.0.0.42 uid 1000
    cache
8.8.8.8 via 172.16.0.1 dev eth1
    src 172.16.0.42
";
            let addr: IpAddr = "8.8.8.8".parse().unwrap();
            let hop = parse_linux_route_get(output, &addr).unwrap();

            match hop {
                NextHop::Gateway { address, interface } => {
                    assert_eq!(address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                    assert_eq!(interface, "wlan0");
                }
                _ => panic!("expected Gateway from first block, got {hop:?}"),
            }
        }

        #[test]
        fn find_token_value_present() {
            let tokens = vec!["8.8.8.8", "via", "192.168.1.1", "dev", "eth0"];
            assert_eq!(find_token_value(&tokens, "via"), Some("192.168.1.1"));
            assert_eq!(find_token_value(&tokens, "dev"), Some("eth0"));
        }

        #[test]
        fn find_token_value_absent() {
            let tokens = vec!["192.168.1.5", "dev", "eth0"];
            assert_eq!(find_token_value(&tokens, "via"), None);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    mod bsd_parser {
        use super::*;

        #[test]
        fn ipv4_gateway() {
            let output = "\
   route to: 8.8.8.8
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
 recvpipe  sendpipe  ssthresh  rtt,msec    mtu        weight    expire
       0         0         0         0      1500         1         0
";
            let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            let hop = parse_bsd_route_get(output, &addr).unwrap();

            match hop {
                NextHop::Gateway { address, interface } => {
                    assert_eq!(address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                    assert_eq!(interface, "en0");
                }
                _ => panic!("expected Gateway, got {hop:?}"),
            }
        }

        #[test]
        fn ipv4_onlink() {
            let output = "\
   route to: 192.168.1.5
destination: 192.168.1.0
       mask: 255.255.255.0
  interface: en0
      flags: <UP,DONE,CLONING>
 recvpipe  sendpipe  ssthresh  rtt,msec    mtu        weight    expire
       0         0         0         0      1500         1         0
";
            let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
            let hop = parse_bsd_route_get(output, &addr).unwrap();

            match hop {
                NextHop::OnLink { interface } => {
                    assert_eq!(interface, "en0");
                }
                _ => panic!("expected OnLink, got {hop:?}"),
            }
        }

        #[test]
        fn ipv6_gateway() {
            let output = "\
   route to: 2001:4860:4860::8888
destination: default
    gateway: fe80::1%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
";
            let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
            let hop = parse_bsd_route_get(output, &addr).unwrap();

            match hop {
                NextHop::Gateway { address, interface } => {
                    assert_eq!(
                        address,
                        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
                    );
                    assert_eq!(interface, "en0");
                }
                _ => panic!("expected Gateway, got {hop:?}"),
            }
        }

        #[test]
        fn ipv6_onlink() {
            let output = "\
   route to: fe80::5
destination: fe80::
       mask: ffff:ffff:ffff:ffff::
  interface: en0
      flags: <UP,DONE,CLONING>
";
            let addr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5));
            let hop = parse_bsd_route_get(output, &addr).unwrap();

            match hop {
                NextHop::OnLink { interface } => {
                    assert_eq!(interface, "en0");
                }
                _ => panic!("expected OnLink, got {hop:?}"),
            }
        }

        #[test]
        fn ipv4_unspecified_gateway_is_onlink() {
            // FreeBSD can emit `gateway: 0.0.0.0` for directly-reachable
            // destinations; this must resolve to on-link, not Gateway(0.0.0.0).
            let output = "\
   route to: 10.0.0.5
destination: 10.0.0.0
       mask: 255.255.255.0
    gateway: 0.0.0.0
  interface: em0
      flags: <UP,DONE,CLONING>
";
            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
            let hop = parse_bsd_route_get(output, &addr).unwrap();

            match hop {
                NextHop::OnLink { interface } => {
                    assert_eq!(interface, "em0");
                }
                _ => panic!("expected OnLink for unspecified gateway, got {hop:?}"),
            }
        }

        #[test]
        fn ipv6_unspecified_gateway_is_onlink() {
            // Same as above but for IPv6 `::`.
            let output = "\
   route to: 2001:db8::5
destination: 2001:db8::
    gateway: ::
  interface: em0
      flags: <UP,DONE,CLONING>
";
            let addr: IpAddr = "2001:db8::5".parse().unwrap();
            let hop = parse_bsd_route_get(output, &addr).unwrap();

            match hop {
                NextHop::OnLink { interface } => {
                    assert_eq!(interface, "em0");
                }
                _ => panic!("expected OnLink for unspecified IPv6 gateway, got {hop:?}"),
            }
        }

        #[test]
        fn valid_gateway_not_overwritten_by_later_invalid() {
            // If a second `gateway:` line contains an unparsable value, the
            // previously parsed valid gateway must be preserved.
            let output = "\
   route to: 8.8.8.8
destination: default
       mask: default
    gateway: 192.168.1.1
    gateway: link#5
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
";
            let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            let hop = parse_bsd_route_get(output, &addr).unwrap();

            match hop {
                NextHop::Gateway { address, interface } => {
                    assert_eq!(address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                    assert_eq!(interface, "en0");
                }
                _ => panic!("expected Gateway preserved from first line, got {hop:?}"),
            }
        }
    }

    #[test]
    fn next_hop_uses_interface_matches_gateway() {
        let hop = NextHop::Gateway {
            address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            interface: "tun0".to_string(),
        };
        assert!(next_hop_uses_interface(&hop, "tun0"));
        assert!(!next_hop_uses_interface(&hop, "eth0"));
    }

    #[test]
    fn next_hop_uses_interface_matches_onlink() {
        let hop = NextHop::OnLink {
            interface: "tun0".to_string(),
        };
        assert!(next_hop_uses_interface(&hop, "tun0"));
        assert!(!next_hop_uses_interface(&hop, "eth0"));
    }

    #[test]
    fn next_hop_uses_interface_is_case_sensitive() {
        // OS interface names are case-sensitive on Linux/macOS/FreeBSD.
        let hop = NextHop::OnLink {
            interface: "tun0".to_string(),
        };
        assert!(!next_hop_uses_interface(&hop, "TUN0"));
    }

    #[test]
    fn next_hop_uses_interface_empty_disables_check() {
        // An empty tunnel interface name must not match anything; this is
        // the guard that keeps us from rejecting every next-hop when the
        // caller doesn't know the tunnel name yet.
        let hop = NextHop::OnLink {
            interface: "".to_string(),
        };
        assert!(!next_hop_uses_interface(&hop, ""));
    }

    #[cfg(target_os = "linux")]
    mod exclusion_linux {
        use super::*;

        #[test]
        fn add_gateway_ipv4() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "route",
                    "add",
                    "203.0.113.1/32",
                    "via",
                    "192.168.1.1"
                ]
            );
        }

        #[test]
        fn add_gateway_ipv6_link_local() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "-6",
                    "route",
                    "add",
                    "2001:db8::1/128",
                    "via",
                    "fe80::1",
                    "dev",
                    "eth0"
                ]
            );
        }

        #[test]
        fn add_gateway_ipv4_link_local() {
            // An IPv4 link-local gateway (169.254.0.0/16) is ambiguous on
            // multi-homed hosts, so the command must pin the route to the
            // discovered interface with `dev <iface>`.
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "route",
                    "add",
                    "203.0.113.1/32",
                    "via",
                    "169.254.1.1",
                    "dev",
                    "eth0"
                ]
            );
        }

        #[test]
        fn remove_gateway_ipv4_link_local() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Remove);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "route",
                    "delete",
                    "203.0.113.1/32",
                    "via",
                    "169.254.1.1",
                    "dev",
                    "eth0"
                ]
            );
        }

        #[test]
        fn add_gateway_ipv4_non_link_local_no_dev() {
            // A non-link-local IPv4 gateway (e.g., typical 192.168.x.x) is
            // unambiguous and must not add `dev <iface>`.
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "route",
                    "add",
                    "203.0.113.1/32",
                    "via",
                    "192.168.1.1"
                ]
            );
        }

        #[test]
        fn add_gateway_ipv6_global() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xfe)),
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "-6",
                    "route",
                    "add",
                    "2001:db8::1/128",
                    "via",
                    "2001:db8::fe"
                ]
            );
        }

        #[test]
        fn add_onlink_ipv4() {
            let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "wlan0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [IP_COMMAND, "route", "add", "10.0.0.5/32", "dev", "wlan0"]
            );
        }

        #[test]
        fn add_onlink_ipv6() {
            let server = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "-6",
                    "route",
                    "add",
                    "fe80::5/128",
                    "dev",
                    "eth0"
                ]
            );
        }

        #[test]
        fn remove_gateway_ipv4() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Remove);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "route",
                    "delete",
                    "203.0.113.1/32",
                    "via",
                    "192.168.1.1"
                ]
            );
        }

        #[test]
        fn remove_gateway_ipv6_link_local() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Remove);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "-6",
                    "route",
                    "delete",
                    "2001:db8::1/128",
                    "via",
                    "fe80::1",
                    "dev",
                    "eth0"
                ]
            );
        }

        #[test]
        fn remove_onlink_ipv6() {
            let server = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Remove);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "-6",
                    "route",
                    "delete",
                    "fe80::5/128",
                    "dev",
                    "eth0"
                ]
            );
        }

        #[test]
        fn remove_fallback_ipv4_scopes_to_interface() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_remove_fallback_args(&hop, &server);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "route",
                    "delete",
                    "203.0.113.1/32",
                    "dev",
                    "eth0"
                ]
            );
        }

        #[test]
        fn remove_fallback_ipv6_scopes_to_interface() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::OnLink {
                interface: "eth0".to_string(),
            };
            let args = exclusion_route_remove_fallback_args(&hop, &server);
            assert_eq!(
                args,
                [
                    IP_COMMAND,
                    "-6",
                    "route",
                    "delete",
                    "2001:db8::1/128",
                    "dev",
                    "eth0"
                ]
            );
        }
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    mod exclusion_bsd {
        use super::*;

        #[test]
        fn add_gateway_ipv4() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "en0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "add",
                    "-host",
                    "203.0.113.1",
                    "192.168.1.1"
                ]
            );
        }

        #[test]
        fn add_gateway_ipv6_link_local() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                interface: "en0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "add",
                    "-inet6",
                    "-host",
                    "2001:db8::1",
                    "fe80::1%en0"
                ]
            );
        }

        #[test]
        fn add_gateway_ipv6_global() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xfe)),
                interface: "en0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "add",
                    "-inet6",
                    "-host",
                    "2001:db8::1",
                    "2001:db8::fe"
                ]
            );
        }

        #[test]
        fn add_onlink_ipv4() {
            let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "en0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "add",
                    "-host",
                    "10.0.0.5",
                    "-interface",
                    "en0"
                ]
            );
        }

        #[test]
        fn add_onlink_ipv6() {
            let server = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "en0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Add);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "add",
                    "-inet6",
                    "-host",
                    "fe80::5",
                    "-interface",
                    "en0"
                ]
            );
        }

        #[test]
        fn remove_gateway_ipv4() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "en0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Remove);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "delete",
                    "-host",
                    "203.0.113.1",
                    "192.168.1.1"
                ]
            );
        }

        #[test]
        fn remove_gateway_ipv6_link_local() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                interface: "en0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Remove);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "delete",
                    "-inet6",
                    "-host",
                    "2001:db8::1",
                    "fe80::1%en0"
                ]
            );
        }

        #[test]
        fn remove_onlink_ipv6() {
            let server = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "en0".to_string(),
            };
            let args = exclusion_route_cmd_args(&server, &hop, ExclusionAction::Remove);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "delete",
                    "-inet6",
                    "-host",
                    "fe80::5",
                    "-interface",
                    "en0"
                ]
            );
        }

        #[test]
        fn remove_fallback_ipv4_scopes_to_interface() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "en0".to_string(),
            };
            let args = exclusion_route_remove_fallback_args(&hop, &server);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "delete",
                    "-host",
                    "203.0.113.1",
                    "-ifp",
                    "en0"
                ]
            );
        }

        #[test]
        fn remove_fallback_ipv6_scopes_to_interface() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::OnLink {
                interface: "en0".to_string(),
            };
            let args = exclusion_route_remove_fallback_args(&hop, &server);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "delete",
                    "-inet6",
                    "-host",
                    "2001:db8::1",
                    "-ifp",
                    "en0"
                ]
            );
        }
    }

    #[test]
    fn bsd_split_replaces_ipv4_default() {
        let nets = vec!["0.0.0.0/0".parse::<IpNet>().unwrap()];
        let split = bsd_split_default_routes(&nets);
        assert_eq!(split.len(), 2);
        assert_eq!(split[0], "0.0.0.0/1".parse::<IpNet>().unwrap());
        assert_eq!(split[1], "128.0.0.0/1".parse::<IpNet>().unwrap());
    }

    #[test]
    fn bsd_split_replaces_ipv6_default() {
        let nets = vec!["::/0".parse::<IpNet>().unwrap()];
        let split = bsd_split_default_routes(&nets);
        assert_eq!(split.len(), 2);
        assert_eq!(split[0], "::/1".parse::<IpNet>().unwrap());
        assert_eq!(split[1], "8000::/1".parse::<IpNet>().unwrap());
    }

    #[test]
    fn bsd_split_preserves_non_default() {
        let nets = vec![
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "192.168.1.0/24".parse::<IpNet>().unwrap(),
        ];
        let split = bsd_split_default_routes(&nets);
        assert_eq!(split, nets);
    }

    #[test]
    fn bsd_split_mixed() {
        let nets = vec![
            "0.0.0.0/0".parse::<IpNet>().unwrap(),
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "::/0".parse::<IpNet>().unwrap(),
            "fd00::/8".parse::<IpNet>().unwrap(),
        ];
        let split = bsd_split_default_routes(&nets);
        assert_eq!(split.len(), 6);
        assert_eq!(split[0], "0.0.0.0/1".parse::<IpNet>().unwrap());
        assert_eq!(split[1], "128.0.0.0/1".parse::<IpNet>().unwrap());
        assert_eq!(split[2], "10.0.0.0/8".parse::<IpNet>().unwrap());
        assert_eq!(split[3], "::/1".parse::<IpNet>().unwrap());
        assert_eq!(split[4], "8000::/1".parse::<IpNet>().unwrap());
        assert_eq!(split[5], "fd00::/8".parse::<IpNet>().unwrap());
    }

    #[test]
    fn bsd_split_empty() {
        let split = bsd_split_default_routes(&[]);
        assert!(split.is_empty());
    }

    #[test]
    fn covers_address_in_default_route() {
        let nets = vec!["0.0.0.0/0".parse::<IpNet>().unwrap()];
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(any_route_covers_address(&nets, &addr));
    }

    #[test]
    fn covers_address_in_subnet() {
        let nets = vec!["10.0.0.0/8".parse::<IpNet>().unwrap()];
        let addr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(any_route_covers_address(&nets, &addr));
    }

    #[test]
    fn does_not_cover_address_outside_subnet() {
        let nets = vec!["10.0.0.0/8".parse::<IpNet>().unwrap()];
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!any_route_covers_address(&nets, &addr));
    }

    #[test]
    fn covers_ipv6_in_default() {
        let nets = vec!["::/0".parse::<IpNet>().unwrap()];
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(any_route_covers_address(&nets, &addr));
    }

    #[test]
    fn does_not_cover_ipv4_in_ipv6_route() {
        let nets = vec!["::/0".parse::<IpNet>().unwrap()];
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!any_route_covers_address(&nets, &addr));
    }

    #[test]
    fn covers_empty_routes() {
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!any_route_covers_address(&[], &addr));
    }

    #[test]
    fn covers_split_halves_cover_all_ipv4() {
        let nets = vec![
            "0.0.0.0/1".parse::<IpNet>().unwrap(),
            "128.0.0.0/1".parse::<IpNet>().unwrap(),
        ];
        assert!(any_route_covers_address(
            &nets,
            &IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        ));
        assert!(any_route_covers_address(
            &nets,
            &IpAddr::V4(Ipv4Addr::new(200, 0, 0, 1))
        ));
    }

    #[test]
    fn link_local_ipv6_detected() {
        let addr: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_ipv6_link_local(&addr));
    }

    #[test]
    fn global_ipv6_not_link_local() {
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!is_ipv6_link_local(&addr));
    }

    #[test]
    fn ipv4_not_ipv6_link_local() {
        let addr: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!is_ipv6_link_local(&addr));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn link_local_helper_detects_both_families() {
        let v4_ll: IpAddr = "169.254.1.1".parse().unwrap();
        let v6_ll: IpAddr = "fe80::1".parse().unwrap();
        let v4_global: IpAddr = "8.8.8.8".parse().unwrap();
        let v6_global: IpAddr = "2001:db8::1".parse().unwrap();

        assert!(is_link_local(&v4_ll));
        assert!(is_link_local(&v6_ll));
        assert!(!is_link_local(&v4_global));
        assert!(!is_link_local(&v6_global));
    }

    #[test]
    fn already_exists_linux_rtnetlink() {
        assert!(output_indicates_already_exists(
            "RTNETLINK answers: File exists"
        ));
    }

    #[test]
    fn already_exists_bsd_file_exists() {
        assert!(output_indicates_already_exists(
            "route: writing to routing socket: File exists"
        ));
    }

    #[test]
    fn already_exists_bsd_route_already_in_table() {
        assert!(output_indicates_already_exists(
            "route: route already in table"
        ));
    }

    #[test]
    fn already_exists_matches_on_stdout_text() {
        // Some platforms print the duplicate marker to stdout instead of
        // stderr; the detector must treat the text identically whichever
        // stream it came from.  This test asserts the underlying predicate
        // is stream-agnostic; callers (see `add_exclusion_route`) must
        // feed it both streams.
        let stdout_sample = "route: writing to routing socket: File exists";
        assert!(output_indicates_already_exists(stdout_sample));
    }

    #[test]
    fn already_exists_negative() {
        assert!(!output_indicates_already_exists("Network is unreachable"));
        assert!(!output_indicates_already_exists("Permission denied"));
        assert!(!output_indicates_already_exists(""));
    }

    #[test]
    fn not_found_linux_rtnetlink() {
        assert!(output_indicates_not_found(
            "RTNETLINK answers: No such process"
        ));
    }

    #[test]
    fn not_found_bsd_not_in_table() {
        assert!(output_indicates_not_found(
            "route: writing to routing socket: not in table"
        ));
    }

    #[test]
    fn not_found_linux_cannot_find() {
        assert!(output_indicates_not_found(
            "RTNETLINK answers: Cannot find device"
        ));
    }

    #[test]
    fn not_found_negative() {
        assert!(!output_indicates_not_found("Permission denied"));
        assert!(!output_indicates_not_found("File exists"));
        assert!(!output_indicates_not_found(""));
    }

    #[cfg(target_os = "linux")]
    mod user_route_args_linux {
        use super::*;

        #[test]
        fn ipv4_add_argv() {
            let net: IpNet = "10.0.0.0/24".parse().unwrap();
            let gw: IpAddr = "192.168.1.1".parse().unwrap();
            let args = user_route_add_args(&net, &gw);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "add",
                    "-net",
                    "10.0.0.0",
                    "netmask",
                    "255.255.255.0",
                    "gw",
                    "192.168.1.1"
                ]
            );
        }

        #[test]
        fn ipv6_add_argv() {
            let net: IpNet = "2001:db8::/32".parse().unwrap();
            let gw: IpAddr = "2001:db8::1".parse().unwrap();
            let args = user_route_add_args(&net, &gw);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-A",
                    "inet6",
                    "add",
                    "2001:db8::/32",
                    "gw",
                    "2001:db8::1"
                ]
            );
        }
    }

    #[cfg(target_os = "macos")]
    mod user_route_args_macos {
        use super::*;

        #[test]
        fn ipv4_add_argv() {
            let net: IpNet = "10.0.0.0/24".parse().unwrap();
            let gw: IpAddr = "192.168.1.1".parse().unwrap();
            let args = user_route_add_args(&net, &gw);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "add",
                    "-net",
                    "10.0.0.0",
                    "-netmask",
                    "255.255.255.0",
                    "192.168.1.1"
                ]
            );
        }

        #[test]
        fn ipv6_add_argv() {
            let net: IpNet = "2001:db8::/32".parse().unwrap();
            let gw: IpAddr = "2001:db8::1".parse().unwrap();
            let args = user_route_add_args(&net, &gw);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "-n",
                    "add",
                    "-inet6",
                    "2001:db8::/32",
                    "2001:db8::1"
                ]
            );
        }
    }

    #[cfg(target_os = "freebsd")]
    mod user_route_args_freebsd {
        use super::*;

        #[test]
        fn ipv4_add_argv() {
            let net: IpNet = "10.0.0.0/24".parse().unwrap();
            let gw: IpAddr = "192.168.1.1".parse().unwrap();
            let args = user_route_add_args(&net, &gw);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "add",
                    "-net",
                    "10.0.0.0",
                    "-netmask",
                    "255.255.255.0",
                    "192.168.1.1"
                ]
            );
        }

        #[test]
        fn ipv6_add_argv() {
            let net: IpNet = "2001:db8::/32".parse().unwrap();
            let gw: IpAddr = "2001:db8::1".parse().unwrap();
            let args = user_route_add_args(&net, &gw);
            assert_eq!(
                args,
                [
                    ROUTE_COMMAND,
                    "add",
                    "-inet6",
                    "2001:db8::/32",
                    "2001:db8::1"
                ]
            );
        }
    }
}
