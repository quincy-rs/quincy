use crate::Result;
use crate::error::RouteError;
use crate::network::route::{InstalledExclusionRoute, NextHop};
use crate::utils::command::run_command;
use ipnet::IpNet;
use serde::Deserialize;
use std::net::IpAddr;
use std::process::Output;
use std::str::FromStr;
use tracing::warn;

/// Command name for Windows PowerShell.
const POWERSHELL_COMMAND: &str = "powershell.exe";

/// Adds a list of routes to the routing table, optionally installing an
/// exclusion host-route for the VPN server first.
///
/// When `remote_address` is `Some(addr)`, the function looks up the current
/// next-hop for `addr` and installs a pinning host-route before adding any
/// user routes.
///
/// If the exclusion route cannot be installed **and** the user routes would
/// cover `remote_address`, a hard [`RouteError::ExclusionRequired`] error is
/// returned.  If the routes do **not** cover the server, the function logs a
/// warning and continues without the exclusion route.
///
/// If a later user-route addition fails after the exclusion route was
/// successfully installed, the exclusion route is removed before the
/// original error is returned.
///
/// ### Arguments
/// - `networks` - the networks to be routed through the gateway
/// - `gateway` - the gateway to be used for the routes
/// - `interface_name` - the name of the interface to add the routes to
/// - `remote_address` - optional VPN server address requiring an exclusion route
pub fn add_routes(
    networks: &[IpNet],
    gateway: &IpAddr,
    interface_name: &str,
    remote_address: Option<IpAddr>,
) -> Result<Option<InstalledExclusionRoute>> {
    // Resolve the tunnel interface index up front so exclusion installation
    // can reject self-referential resolutions (route to the server that goes
    // back through our own TUN device).
    let tunnel_if_index = resolve_interface_index(interface_name)?;

    let exclusion = match remote_address {
        Some(server) => match install_exclusion_for_server(&server, tunnel_if_index) {
            Ok(token) => Some(token),
            Err(err) => {
                if any_route_covers_address(networks, &server) {
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

    if let Err(add_err) = add_user_routes_with_index(networks, gateway, tunnel_if_index) {
        // Roll back the exclusion route if it was installed.
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

    Ok(exclusion)
}

/// Attempts to discover the current next-hop for `server` and install an
/// exclusion host-route via that next-hop.
///
/// Rejects **self-referential** resolutions, where the OS reports a route to
/// the server that would form a loop through the VPN itself. Pinning
/// traffic via such a route cannot exclude the server from the tunnel.
/// Two cases are rejected:
///
/// - The next-hop gateway address equals the server address (`server` is its
///   own gateway), which is semantically meaningless.
/// - The resolved interface index equals the tunnel interface index, which
///   would pin server traffic back into our own TUN device.
fn install_exclusion_for_server(
    server: &IpAddr,
    tunnel_if_index: u32,
) -> Result<InstalledExclusionRoute> {
    let next_hop = get_route_to(server)?;

    if is_self_referential_next_hop(server, &next_hop, tunnel_if_index) {
        return Err(RouteError::PlatformError {
            message: format!(
                "route-to-server lookup for {server} resolved to a self-referential \
                 next-hop ({next_hop:?}); refusing to install exclusion route"
            ),
        }
        .into());
    }

    add_exclusion_route(server, &next_hop)
}

/// Returns `true` when `next_hop` cannot be used as an exclusion-route
/// target because it would form a loop, either via the server itself or
/// via the tunnel interface.
fn is_self_referential_next_hop(server: &IpAddr, next_hop: &NextHop, tunnel_if_index: u32) -> bool {
    let tunnel_index_str = tunnel_if_index.to_string();

    match next_hop {
        NextHop::Gateway { address, interface } => {
            address == server || interface == &tunnel_index_str
        }
        NextHop::OnLink { interface } => interface == &tunnel_index_str,
    }
}

/// Adds user routes in a single batched PowerShell invocation, using a
/// pre-resolved tunnel interface index.
fn add_user_routes_with_index(networks: &[IpNet], gateway: &IpAddr, if_index: u32) -> Result<()> {
    if networks.is_empty() {
        return Ok(());
    }

    let script = build_user_routes_script(networks, gateway, if_index);
    let args = vec!["-NoProfile", "-NonInteractive", "-Command", &script];

    let output = run_command(POWERSHELL_COMMAND, &args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute user route add command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for user route add command: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RouteError::AddFailed {
            destination: format!("{} network(s) via ifIndex {}", networks.len(), if_index),
            message: stderr.trim().to_string(),
        }
        .into());
    }

    Ok(())
}

/// Returns `true` if any network in `routes` contains `address`.
pub(crate) fn any_route_covers_address(routes: &[IpNet], address: &IpAddr) -> bool {
    routes.iter().any(|net| net.contains(address))
}

/// Escapes a string for use inside a PowerShell single-quoted literal.
///
/// In PowerShell single-quoted strings the only special character is the
/// single quote itself, which is escaped by doubling it (`'` → `''`).
/// PowerShell also treats several Unicode smart-quote code points as
/// single-quote delimiters, so those are replaced as well to prevent
/// accidental string termination.
fn escape_ps_single_quoted(value: &str) -> String {
    value
        .replace('\'', "''") // U+0027 APOSTROPHE
        .replace('\u{2018}', "''") // LEFT SINGLE QUOTATION MARK
        .replace('\u{2019}', "''") // RIGHT SINGLE QUOTATION MARK
        .replace('\u{201A}', "''") // SINGLE LOW-9 QUOTATION MARK
        .replace('\u{201B}', "''") // SINGLE HIGH-REVERSED-9 QUOTATION MARK
}

/// Resolves a Windows network adapter name to its interface index.
///
/// Runs `Get-NetAdapter -Name '<name>' -ErrorAction Stop` and extracts the
/// `ifIndex` property.
fn resolve_interface_index(interface_name: &str) -> Result<u32> {
    let safe_name = escape_ps_single_quoted(interface_name);
    let ps_script = format!(
        "$ErrorActionPreference = 'Stop'; (Get-NetAdapter -Name '{}' -ErrorAction Stop).ifIndex",
        safe_name
    );
    let args = vec!["-NoProfile", "-NonInteractive", "-Command", &ps_script];

    let output = run_command(POWERSHELL_COMMAND, &args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to resolve interface index for '{interface_name}': {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for interface index resolution: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RouteError::PlatformError {
            message: format!(
                "failed to resolve interface index for '{interface_name}': {}",
                stderr.trim()
            ),
        }
        .into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.trim().parse::<u32>().map_err(|e| {
        RouteError::PlatformError {
            message: format!(
                "unexpected interface index value '{}' for '{interface_name}': {e}",
                stdout.trim()
            ),
        }
        .into()
    })
}

/// Builds a PowerShell script that adds multiple routes in a single
/// invocation using `New-NetRoute`.
///
/// Each route is added with `-PolicyStore ActiveStore` so it is not
/// persisted across reboots, matching the active-only lifecycle.
///
/// The script uses `$ErrorActionPreference = 'Stop'` so the first failure
/// terminates execution immediately.
fn build_user_routes_script(networks: &[IpNet], gateway: &IpAddr, interface_index: u32) -> String {
    let mut script = String::from("$ErrorActionPreference = 'Stop'; ");
    let gateway_str = gateway.to_string();

    for network in networks {
        script.push_str(&format!(
            "New-NetRoute -DestinationPrefix '{}' -InterfaceIndex {} -NextHop '{}' -PolicyStore ActiveStore; ",
            network, interface_index, gateway_str
        ));
    }

    script
}

/// Queries the system routing table for the next hop to reach `address`.
///
/// Runs PowerShell `Find-NetRoute -RemoteIPAddress <addr>` and parses the
/// JSON output to determine whether traffic goes via a gateway or is on-link.
pub fn get_route_to(address: &IpAddr) -> Result<NextHop> {
    let output = run_find_net_route(address)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_find_net_route_json(&stdout, address)
}

/// Executes `Find-NetRoute` via PowerShell and returns its raw output.
fn run_find_net_route(address: &IpAddr) -> Result<Output> {
    let addr_str = address.to_string();
    let ps_script = format!(
        "Find-NetRoute -RemoteIPAddress '{}' | Select-Object -Property InterfaceIndex,NextHop | ConvertTo-Json",
        addr_str
    );

    let args = vec!["-NoProfile", "-NonInteractive", "-Command", &ps_script];

    let output = run_command(POWERSHELL_COMMAND, &args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute Find-NetRoute command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for Find-NetRoute command: {e}"),
        })?;

    if !output.status.success() {
        return Err(RouteError::NotFound {
            destination: addr_str,
        }
        .into());
    }

    Ok(output)
}

/// A single row from `Find-NetRoute … | ConvertTo-Json`.
///
/// `NextHop` is nullable because `Find-NetRoute` can return non-route rows
/// (e.g. interface metadata) where the field is absent or `null`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct FindNetRouteEntry {
    interface_index: u32,
    next_hop: Option<String>,
}

/// Parses the JSON output of `Find-NetRoute` into a `NextHop`.
///
/// `Find-NetRoute` may return a single JSON object or an array of objects.
/// Non-route rows (where `NextHop` is `null`) are skipped; the first entry
/// with a present `NextHop` that is a valid IP address is used.
/// A `NextHop` of `0.0.0.0` (IPv4) or `::` (IPv6) means the destination is
/// directly reachable (on-link).
fn parse_find_net_route_json(json_output: &str, address: &IpAddr) -> Result<NextHop> {
    let entries = parse_entries(json_output).map_err(|e| RouteError::PlatformError {
        message: format!("failed to parse Find-NetRoute output for {address}: {e}"),
    })?;

    // Find the first entry with a non-null NextHop that parses as an IP.
    let (entry, next_hop_str) = entries
        .iter()
        .filter_map(|e| e.next_hop.as_deref().map(|nh| (e, nh)))
        .find(|(_, nh)| is_onlink_next_hop(nh) || IpAddr::from_str(nh).is_ok())
        .ok_or_else(|| RouteError::NotFound {
            destination: address.to_string(),
        })?;

    let interface = entry.interface_index.to_string();

    if is_onlink_next_hop(next_hop_str) {
        Ok(NextHop::OnLink { interface })
    } else {
        // Safe to unwrap: the `find` above already verified this parses.
        let gw_addr = IpAddr::from_str(next_hop_str).map_err(|_| RouteError::PlatformError {
            message: format!(
                "invalid NextHop address '{}' in Find-NetRoute output for {address}",
                next_hop_str
            ),
        })?;
        Ok(NextHop::Gateway {
            address: gw_addr,
            interface,
        })
    }
}

/// Deserializes `Find-NetRoute` JSON, handling both a single object and an
/// array of objects (PowerShell emits a bare object when there is exactly one
/// result).
fn parse_entries(json_output: &str) -> std::result::Result<Vec<FindNetRouteEntry>, String> {
    let trimmed = json_output.trim();
    if trimmed.is_empty() {
        return Err("empty output".to_string());
    }

    // Try array first, then single object.
    if let Ok(entries) = serde_json::from_str::<Vec<FindNetRouteEntry>>(trimmed) {
        return Ok(entries);
    }

    serde_json::from_str::<FindNetRouteEntry>(trimmed)
        .map(|e| vec![e])
        .map_err(|e| e.to_string())
}

/// Returns `true` when the `NextHop` value indicates an on-link destination.
///
/// PowerShell reports `0.0.0.0` for IPv4 on-link routes and `::` for IPv6.
fn is_onlink_next_hop(next_hop: &str) -> bool {
    matches!(next_hop, "0.0.0.0" | "::")
}

/// Installs a host route (`/32` for IPv4, `/128` for IPv6) that pins traffic
/// for `server` to the given `next_hop`, preventing the VPN tunnel from
/// capturing its own control-plane traffic.
///
/// If a route for the same destination already exists in the `ActiveStore`
/// on the intended interface, this function returns
/// [`RouteError::AddFailed`] rather than adopting the pre-existing route.
/// Quincy refuses to claim ownership of routes it did not install, even if
/// their next-hop happens to match. Returning an ownership token for a
/// pre-existing route would later cause cleanup to remove a route Quincy
/// does not own.
///
/// Duplicate detection is performed inside the PowerShell script using the
/// language-neutral [`Microsoft.Management.Infrastructure.NativeErrorCode`]
/// enum, which makes the check independent of the host's display locale.
pub fn add_exclusion_route(server: &IpAddr, next_hop: &NextHop) -> Result<InstalledExclusionRoute> {
    let script = exclusion_route_add_script(server, next_hop);
    let args = vec!["-NoProfile", "-NonInteractive", "-Command", &script];

    let output = run_command(POWERSHELL_COMMAND, &args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute exclusion route add command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for exclusion route add command: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RouteError::AddFailed {
            destination: server.to_string(),
            message: stderr.trim().to_string(),
        }
        .into());
    }

    Ok(InstalledExclusionRoute {
        destination: *server,
        next_hop: next_hop.clone(),
    })
}

/// Removes a previously installed exclusion host route.
///
/// If the next-hop-specific removal fails (e.g. the gateway changed due to
/// DHCP renewal or network roaming), a fallback removal by destination
/// prefix alone is attempted so the route does not leak.  The fallback
/// treats `NotFound` as benign (the route is already absent, which matches
/// the desired end state), while any other failure is reported as
/// [`RouteError::RemoveFailed`].
pub fn remove_exclusion_route(exclusion: &InstalledExclusionRoute) -> Result<()> {
    let script = exclusion_route_remove_script(&exclusion.destination, &exclusion.next_hop);
    let args = vec!["-NoProfile", "-NonInteractive", "-Command", &script];

    let output = run_command(POWERSHELL_COMMAND, &args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute exclusion route remove command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for exclusion route remove command: {e}"),
        })?;

    if output.status.success() {
        return Ok(());
    }

    // The gateway may have changed since the route was installed, so retry
    // with a destination-only removal to avoid leaking the stale route.
    warn!(
        destination = %exclusion.destination,
        "next-hop-specific exclusion route removal failed; retrying with destination-only removal"
    );

    let fallback_script =
        exclusion_route_remove_fallback_script(&exclusion.destination, &exclusion.next_hop);
    let fallback_args = vec![
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        &fallback_script,
    ];

    let fallback_output = run_command(POWERSHELL_COMMAND, &fallback_args)
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to execute fallback exclusion route remove command: {e}"),
        })?
        .wait_with_output()
        .map_err(|e| RouteError::PlatformError {
            message: format!("failed to wait for fallback exclusion route remove command: {e}"),
        })?;

    if !fallback_output.status.success() {
        return Err(RouteError::RemoveFailed {
            destination: exclusion.destination.to_string(),
        }
        .into());
    }

    Ok(())
}

/// Returns the host-route destination prefix for `server` (`/32` for IPv4,
/// `/128` for IPv6).
fn host_prefix_for(server: &IpAddr) -> String {
    match server {
        IpAddr::V4(_) => format!("{server}/32"),
        IpAddr::V6(_) => format!("{server}/128"),
    }
}

/// Returns the interface index string carried by `next_hop`, regardless of
/// whether it's a gateway or an on-link route.
fn interface_index_of(next_hop: &NextHop) -> &str {
    match next_hop {
        NextHop::Gateway { interface, .. } | NextHop::OnLink { interface } => interface,
    }
}

/// Builds the PowerShell script for adding an exclusion host route.
///
/// Produces a `New-NetRoute` command with `$ErrorActionPreference = 'Stop'`
/// so any failure, including the route already existing, surfaces as a
/// non-zero script exit.  The Rust caller ([`add_exclusion_route`]) then
/// reports an `AddFailed`, which the higher-level caller ([`add_routes`])
/// handles via the existing exclusion-install fallback path.
///
/// Duplicate routes are **not adopted**: Quincy refuses to mint an
/// ownership token for a route it did not install, so the cleanup path can
/// never remove a route owned by another actor.  `AlreadyExists` is
/// detected using the CIM [`NativeErrorCode`] enum purely so the error
/// message produced on non-English hosts remains stable and useful; the
/// enum check is **not** used to adopt ownership.
///
/// Keeping this as a pure function makes it testable without executing
/// real commands.
///
/// [`NativeErrorCode`]: https://learn.microsoft.com/dotnet/api/microsoft.management.infrastructure.nativeerrorcode
fn exclusion_route_add_script(server: &IpAddr, next_hop: &NextHop) -> String {
    let prefix = host_prefix_for(server);
    let interface_index = interface_index_of(next_hop);

    let next_hop_arg = if let NextHop::Gateway { address, .. } = next_hop {
        format!(" -NextHop '{address}'")
    } else {
        String::new()
    };

    // Try-body creates the route; any failure (including AlreadyExists) is
    // caught so we can emit a locale-independent, diagnostic error message
    // before exiting non-zero.
    let try_body = format!(
        "New-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex {interface_index} -PolicyStore ActiveStore{next_hop_arg} | Out-Null"
    );

    // On AlreadyExists, produce a clear message that explains why Quincy
    // refuses to adopt a pre-existing route.  For any other CimException
    // we re-throw so the original error surfaces verbatim.
    let catch_body = format!(
        "if ($_.Exception.NativeErrorCode -eq [Microsoft.Management.Infrastructure.NativeErrorCode]::AlreadyExists) {{ \
         Write-Error \"refusing to adopt a pre-existing exclusion route for '{prefix}' on ifIndex {interface_index} that Quincy did not install\"; \
         exit 1 \
         }}; \
         throw"
    );

    format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ {try_body} }} \
         catch [Microsoft.Management.Infrastructure.CimException] {{ {catch_body} }}"
    )
}

/// Builds the PowerShell script for removing an exclusion host route.
///
/// Produces a `Remove-NetRoute` command with `-DestinationPrefix`,
/// `-InterfaceIndex`, `-PolicyStore ActiveStore`, `-NextHop` (when the
/// next-hop is a gateway), and `-Confirm:$false` to suppress the interactive
/// prompt.  The explicit `-PolicyStore ActiveStore` scopes removal to
/// Quincy-owned routes in the active store.
///
/// The primary script intentionally does **not** swallow a `NotFound` CIM
/// error.  If the next-hop no longer matches (e.g. DHCP renewal), the
/// primary removal reports `NotFound` and the caller then runs
/// [`exclusion_route_remove_fallback_script`], which omits `-NextHop` and
/// does swallow `NotFound` as benign.
fn exclusion_route_remove_script(server: &IpAddr, next_hop: &NextHop) -> String {
    let prefix = host_prefix_for(server);
    let interface_index = interface_index_of(next_hop);

    let mut script = format!(
        "Remove-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex {interface_index} -PolicyStore ActiveStore"
    );

    if let NextHop::Gateway { address, .. } = next_hop {
        script.push_str(&format!(" -NextHop '{address}'"));
    }

    script.push_str(" -Confirm:$false");
    script
}

/// Builds a fallback PowerShell script that removes an exclusion host route
/// without specifying the next hop.
///
/// Used when the primary removal (which includes `-NextHop`) fails because
/// the gateway changed after installation (DHCP renewal, network roaming)
/// or because the route is already absent.
///
/// The fallback intentionally scopes removal to:
/// - the **intended interface index** (the one we installed the route on),
/// - the **`ActiveStore`** policy store (the store Quincy writes to),
///
/// so it only touches Quincy-owned routes on the VPN's physical interface.
/// Pre-existing routes on other interfaces, or persistent routes managed by
/// the OS/user, are never removed by this fallback.
///
/// A `NotFound` CIM error from `Remove-NetRoute` is swallowed as benign:
/// the route is already absent, which is the desired end state.  Detection
/// uses the locale-independent
/// [`Microsoft.Management.Infrastructure.NativeErrorCode`] enum so the
/// behaviour is stable on non-English Windows hosts.  Any other failure
/// still surfaces to the Rust caller as a non-zero script exit.
fn exclusion_route_remove_fallback_script(server: &IpAddr, next_hop: &NextHop) -> String {
    let prefix = host_prefix_for(server);
    let interface_index = interface_index_of(next_hop);

    let remove_cmd = format!(
        "Remove-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex {interface_index} -PolicyStore ActiveStore -Confirm:$false"
    );

    // Swallow NotFound (route already absent) and re-throw anything else.
    format!(
        "$ErrorActionPreference = 'Stop'; \
         try {{ {remove_cmd} }} \
         catch [Microsoft.Management.Infrastructure.CimException] {{ \
         if ($_.Exception.NativeErrorCode -ne [Microsoft.Management.Infrastructure.NativeErrorCode]::NotFound) {{ throw }} \
         }}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_entries_single_object() {
        let json = r#"{"InterfaceIndex": 12, "NextHop": "192.168.1.1"}"#;
        let entries = parse_entries(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].interface_index, 12);
        assert_eq!(entries[0].next_hop.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn parse_entries_array() {
        let json = r#"[
            {"InterfaceIndex": 12, "NextHop": "192.168.1.1"},
            {"InterfaceIndex": 1, "NextHop": "0.0.0.0"}
        ]"#;
        let entries = parse_entries(json).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].interface_index, 12);
        assert_eq!(entries[0].next_hop.as_deref(), Some("192.168.1.1"));
        assert_eq!(entries[1].interface_index, 1);
        assert_eq!(entries[1].next_hop.as_deref(), Some("0.0.0.0"));
    }

    #[test]
    fn parse_entries_null_next_hop() {
        let json = r#"{"InterfaceIndex": 3, "NextHop": null}"#;
        let entries = parse_entries(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].interface_index, 3);
        assert_eq!(entries[0].next_hop, None);
    }

    #[test]
    fn parse_entries_mixed_null_and_valid() {
        let json = r#"[
            {"InterfaceIndex": 3, "NextHop": null},
            {"InterfaceIndex": 12, "NextHop": "192.168.1.1"},
            {"InterfaceIndex": 1, "NextHop": "0.0.0.0"}
        ]"#;
        let entries = parse_entries(json).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].next_hop, None);
        assert_eq!(entries[1].next_hop.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn parse_entries_empty_string() {
        assert!(parse_entries("").is_err());
        assert!(parse_entries("   ").is_err());
    }

    #[test]
    fn parse_entries_invalid_json() {
        assert!(parse_entries("not json").is_err());
    }

    #[test]
    fn onlink_ipv4_zero() {
        assert!(is_onlink_next_hop("0.0.0.0"));
    }

    #[test]
    fn onlink_ipv6_unspecified() {
        assert!(is_onlink_next_hop("::"));
    }

    #[test]
    fn not_onlink_real_gateway() {
        assert!(!is_onlink_next_hop("192.168.1.1"));
        assert!(!is_onlink_next_hop("fe80::1"));
    }

    #[test]
    fn ipv4_gateway() {
        // Captured sample: Find-NetRoute for 8.8.8.8 via gateway 192.168.1.1
        let json = r#"[
            {
                "InterfaceIndex": 12,
                "NextHop": "192.168.1.1"
            },
            {
                "InterfaceIndex": 1,
                "NextHop": "0.0.0.0"
            }
        ]"#;
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let hop = parse_find_net_route_json(json, &addr).unwrap();

        match hop {
            NextHop::Gateway { address, interface } => {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(interface, "12");
            }
            _ => panic!("expected Gateway, got {hop:?}"),
        }
    }

    #[test]
    fn ipv4_onlink() {
        // Captured sample: Find-NetRoute for a directly-connected host
        let json = r#"{
            "InterfaceIndex": 5,
            "NextHop": "0.0.0.0"
        }"#;
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        let hop = parse_find_net_route_json(json, &addr).unwrap();

        match hop {
            NextHop::OnLink { interface } => {
                assert_eq!(interface, "5");
            }
            _ => panic!("expected OnLink, got {hop:?}"),
        }
    }

    #[test]
    fn ipv6_gateway() {
        // Captured sample: Find-NetRoute for 2001:4860:4860::8888 via gateway
        let json = r#"[
            {
                "InterfaceIndex": 7,
                "NextHop": "fe80::1"
            },
            {
                "InterfaceIndex": 1,
                "NextHop": "::"
            }
        ]"#;
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
        let hop = parse_find_net_route_json(json, &addr).unwrap();

        match hop {
            NextHop::Gateway { address, interface } => {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
                );
                assert_eq!(interface, "7");
            }
            _ => panic!("expected Gateway, got {hop:?}"),
        }
    }

    #[test]
    fn ipv6_onlink() {
        // Captured sample: Find-NetRoute for a link-local neighbor
        let json = r#"{
            "InterfaceIndex": 7,
            "NextHop": "::"
        }"#;
        let addr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5));
        let hop = parse_find_net_route_json(json, &addr).unwrap();

        match hop {
            NextHop::OnLink { interface } => {
                assert_eq!(interface, "7");
            }
            _ => panic!("expected OnLink, got {hop:?}"),
        }
    }

    #[test]
    fn empty_json_returns_error() {
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(parse_find_net_route_json("", &addr).is_err());
    }

    #[test]
    fn empty_array_returns_not_found() {
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(parse_find_net_route_json("[]", &addr).is_err());
    }

    #[test]
    fn invalid_next_hop_address_returns_error() {
        let json = r#"{"InterfaceIndex": 12, "NextHop": "not-an-ip"}"#;
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(parse_find_net_route_json(json, &addr).is_err());
    }

    #[test]
    fn null_next_hop_single_entry_returns_not_found() {
        let json = r#"{"InterfaceIndex": 3, "NextHop": null}"#;
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(parse_find_net_route_json(json, &addr).is_err());
    }

    #[test]
    fn null_next_hop_skipped_picks_valid_gateway() {
        // Real PowerShell output: first row is interface metadata with null
        // NextHop, second row is the actual route entry.
        let json = r#"[
            {"InterfaceIndex": 3, "NextHop": null},
            {"InterfaceIndex": 12, "NextHop": "192.168.1.1"},
            {"InterfaceIndex": 1, "NextHop": "0.0.0.0"}
        ]"#;
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let hop = parse_find_net_route_json(json, &addr).unwrap();

        match hop {
            NextHop::Gateway { address, interface } => {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(interface, "12");
            }
            _ => panic!("expected Gateway, got {hop:?}"),
        }
    }

    #[test]
    fn null_next_hop_skipped_picks_valid_onlink() {
        // All non-route rows precede the on-link entry.
        let json = r#"[
            {"InterfaceIndex": 3, "NextHop": null},
            {"InterfaceIndex": 5, "NextHop": "0.0.0.0"}
        ]"#;
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        let hop = parse_find_net_route_json(json, &addr).unwrap();

        match hop {
            NextHop::OnLink { interface } => {
                assert_eq!(interface, "5");
            }
            _ => panic!("expected OnLink, got {hop:?}"),
        }
    }

    #[test]
    fn all_null_next_hops_returns_not_found() {
        let json = r#"[
            {"InterfaceIndex": 3, "NextHop": null},
            {"InterfaceIndex": 5, "NextHop": null}
        ]"#;
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(parse_find_net_route_json(json, &addr).is_err());
    }

    #[test]
    fn invalid_next_hop_skipped_picks_valid() {
        // An entry with a non-IP string is skipped in favour of a valid one.
        let json = r#"[
            {"InterfaceIndex": 3, "NextHop": "not-an-ip"},
            {"InterfaceIndex": 12, "NextHop": "10.0.0.1"}
        ]"#;
        let addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let hop = parse_find_net_route_json(json, &addr).unwrap();

        match hop {
            NextHop::Gateway { address, interface } => {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                assert_eq!(interface, "12");
            }
            _ => panic!("expected Gateway, got {hop:?}"),
        }
    }

    mod exclusion_windows {
        use super::*;

        #[test]
        fn add_gateway_ipv4_contains_new_netroute() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "12".to_string(),
            };
            let script = exclusion_route_add_script(&server, &hop);
            assert!(script.contains(
                "New-NetRoute -DestinationPrefix '203.0.113.1/32' -InterfaceIndex 12 -PolicyStore ActiveStore -NextHop '192.168.1.1'"
            ));
        }

        #[test]
        fn add_gateway_ipv6_contains_new_netroute() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                interface: "7".to_string(),
            };
            let script = exclusion_route_add_script(&server, &hop);
            assert!(script.contains(
                "New-NetRoute -DestinationPrefix '2001:db8::1/128' -InterfaceIndex 7 -PolicyStore ActiveStore -NextHop 'fe80::1'"
            ));
        }

        #[test]
        fn add_onlink_ipv4_omits_next_hop() {
            let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "5".to_string(),
            };
            let script = exclusion_route_add_script(&server, &hop);
            assert!(script.contains(
                "New-NetRoute -DestinationPrefix '10.0.0.5/32' -InterfaceIndex 5 -PolicyStore ActiveStore |"
            ));
            assert!(!script.contains("-NextHop"));
        }

        #[test]
        fn add_onlink_ipv6_omits_next_hop() {
            let server = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "7".to_string(),
            };
            let script = exclusion_route_add_script(&server, &hop);
            assert!(script.contains(
                "New-NetRoute -DestinationPrefix 'fe80::5/128' -InterfaceIndex 7 -PolicyStore ActiveStore |"
            ));
            assert!(!script.contains("-NextHop"));
        }

        #[test]
        fn add_script_contains_active_store_policy() {
            // Regression: exclusion routes must use ActiveStore to avoid
            // persisting across reboots.
            let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                interface: "3".to_string(),
            };
            let script = exclusion_route_add_script(&server, &hop);
            assert!(
                script.contains("-PolicyStore ActiveStore"),
                "exclusion add script must include -PolicyStore ActiveStore: {script}"
            );
        }

        #[test]
        fn add_script_uses_locale_independent_duplicate_detection() {
            // Regression: duplicate detection must use the CIM NativeErrorCode
            // enum, not English-language error text, so the behavior is stable
            // on non-English Windows hosts.
            let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                interface: "3".to_string(),
            };
            let script = exclusion_route_add_script(&server, &hop);
            assert!(
                script.contains("[Microsoft.Management.Infrastructure.CimException]"),
                "script must catch CimException specifically: {script}"
            );
            assert!(
                script.contains(
                    "[Microsoft.Management.Infrastructure.NativeErrorCode]::AlreadyExists"
                ),
                "script must compare against AlreadyExists enum value: {script}"
            );
            assert!(
                !script.to_lowercase().contains("already exists"),
                "script must not rely on English 'already exists' text: {script}"
            );
        }

        #[test]
        fn add_script_refuses_to_adopt_duplicate_routes() {
            // Regression: a duplicate/pre-existing route must never
            // be adopted, even if its NextHop matches. Doing so would mint
            // an ownership token that later removes a route Quincy did not
            // install.  The script must:
            //  - detect AlreadyExists via the CIM NativeErrorCode enum,
            //  - NOT look up the existing route with Get-NetRoute,
            //  - NOT compare NextHops to "verify ownership",
            //  - exit non-zero so the Rust caller returns AddFailed.
            let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                interface: "3".to_string(),
            };
            let script = exclusion_route_add_script(&server, &hop);

            assert!(
                !script.contains("Get-NetRoute"),
                "add script must not inspect existing routes for adoption: {script}"
            );
            assert!(
                !script.contains("$_.NextHop -eq"),
                "add script must not compare NextHops to decide adoption: {script}"
            );
            assert!(
                script.contains(
                    "[Microsoft.Management.Infrastructure.NativeErrorCode]::AlreadyExists"
                ),
                "add script must still detect AlreadyExists via NativeErrorCode: {script}"
            );
            assert!(
                script.contains("exit 1"),
                "add script must exit non-zero on AlreadyExists: {script}"
            );
        }

        #[test]
        fn add_script_rethrows_non_already_exists_cim_errors() {
            // Regression: any CimException other than AlreadyExists must be
            // re-thrown so the original error surfaces verbatim and is not
            // silently reinterpreted as a duplicate.
            let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                interface: "3".to_string(),
            };
            let script = exclusion_route_add_script(&server, &hop);
            assert!(
                script.contains("throw"),
                "add script must re-throw non-AlreadyExists CIM errors: {script}"
            );
        }

        #[test]
        fn remove_gateway_ipv4() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "12".to_string(),
            };
            let script = exclusion_route_remove_script(&server, &hop);
            assert_eq!(
                script,
                "Remove-NetRoute -DestinationPrefix '203.0.113.1/32' -InterfaceIndex 12 -PolicyStore ActiveStore -NextHop '192.168.1.1' -Confirm:$false"
            );
        }

        #[test]
        fn remove_onlink_ipv6() {
            let server = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "7".to_string(),
            };
            let script = exclusion_route_remove_script(&server, &hop);
            assert_eq!(
                script,
                "Remove-NetRoute -DestinationPrefix 'fe80::5/128' -InterfaceIndex 7 -PolicyStore ActiveStore -Confirm:$false"
            );
        }

        #[test]
        fn remove_gateway_ipv6() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                interface: "7".to_string(),
            };
            let script = exclusion_route_remove_script(&server, &hop);
            assert_eq!(
                script,
                "Remove-NetRoute -DestinationPrefix '2001:db8::1/128' -InterfaceIndex 7 -PolicyStore ActiveStore -NextHop 'fe80::1' -Confirm:$false"
            );
        }

        #[test]
        fn remove_onlink_ipv4() {
            let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "5".to_string(),
            };
            let script = exclusion_route_remove_script(&server, &hop);
            assert_eq!(
                script,
                "Remove-NetRoute -DestinationPrefix '10.0.0.5/32' -InterfaceIndex 5 -PolicyStore ActiveStore -Confirm:$false"
            );
        }

        #[test]
        fn remove_scopes_to_active_store() {
            // Regression: removal must be scoped to the ActiveStore policy
            // store so it never touches persistent/user-owned routes.
            let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                interface: "3".to_string(),
            };
            let script = exclusion_route_remove_script(&server, &hop);
            assert!(
                script.contains("-PolicyStore ActiveStore"),
                "remove script must scope to ActiveStore: {script}"
            );
        }

        #[test]
        fn fallback_remove_ipv4() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "12".to_string(),
            };
            let script = exclusion_route_remove_fallback_script(&server, &hop);
            assert!(script.contains(
                "Remove-NetRoute -DestinationPrefix '203.0.113.1/32' -InterfaceIndex 12 -PolicyStore ActiveStore -Confirm:$false"
            ));
        }

        #[test]
        fn fallback_remove_ipv6() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                interface: "7".to_string(),
            };
            let script = exclusion_route_remove_fallback_script(&server, &hop);
            assert!(script.contains(
                "Remove-NetRoute -DestinationPrefix '2001:db8::1/128' -InterfaceIndex 7 -PolicyStore ActiveStore -Confirm:$false"
            ));
        }

        #[test]
        fn fallback_remove_onlink_ipv4_uses_interface_from_next_hop() {
            let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "5".to_string(),
            };
            let script = exclusion_route_remove_fallback_script(&server, &hop);
            assert!(script.contains(
                "Remove-NetRoute -DestinationPrefix '10.0.0.5/32' -InterfaceIndex 5 -PolicyStore ActiveStore -Confirm:$false"
            ));
        }

        #[test]
        fn fallback_remove_omits_next_hop_but_scopes_interface_and_store() {
            // Regression: fallback must omit -NextHop (so it tolerates
            // gateway changes) while still scoping removal to the intended
            // interface and ActiveStore so it never touches routes on other
            // interfaces or persistent/user-owned routes.
            let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                interface: "3".to_string(),
            };
            let script = exclusion_route_remove_fallback_script(&server, &hop);

            // The only -NextHop occurrence allowed is the NativeErrorCode
            // constant name ("NotFound") or similar, not a -NextHop CLI arg.
            assert!(
                !script.contains(" -NextHop "),
                "fallback script must not pass -NextHop as a CLI arg: {script}"
            );
            assert!(
                script.contains("-InterfaceIndex 3"),
                "fallback script must scope to the intended interface: {script}"
            );
            assert!(
                script.contains("-PolicyStore ActiveStore"),
                "fallback script must scope to ActiveStore: {script}"
            );
        }

        #[test]
        fn fallback_remove_swallows_not_found_benignly() {
            // Regression: if the exclusion route is already absent,
            // Remove-NetRoute raises a CimException with
            // NativeErrorCode::NotFound.  The fallback must swallow that
            // case so teardown does not spuriously report an error when
            // the desired end state is already in place.  Detection stays
            // locale-independent via the CIM NativeErrorCode enum.
            let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                interface: "3".to_string(),
            };
            let script = exclusion_route_remove_fallback_script(&server, &hop);

            assert!(
                script.contains("[Microsoft.Management.Infrastructure.CimException]"),
                "fallback must catch CimException specifically: {script}"
            );
            assert!(
                script.contains("[Microsoft.Management.Infrastructure.NativeErrorCode]::NotFound"),
                "fallback must compare against the NotFound enum value: {script}"
            );
            assert!(
                script.contains("throw"),
                "fallback must re-throw non-NotFound CIM errors: {script}"
            );
            assert!(
                !script.to_lowercase().contains("not found ") // space after
                    && !script.to_lowercase().contains("does not exist")
                    && !script.to_lowercase().contains("object not found"),
                "fallback must not rely on English error text: {script}"
            );
        }

        #[test]
        fn primary_remove_does_not_swallow_not_found() {
            // Regression: the primary remove path must NOT swallow
            // NotFound, because when the gateway has changed the
            // -NextHop-filtered Remove-NetRoute returns NotFound and the
            // fallback (which omits -NextHop) is what should actually remove
            // the route.  If the primary swallowed NotFound we would leak
            // the route on next-hop drift.
            let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                interface: "3".to_string(),
            };
            let script = exclusion_route_remove_script(&server, &hop);

            assert!(
                !script.contains("NativeErrorCode"),
                "primary remove must not inspect NativeErrorCode (must let errors propagate): {script}"
            );
            assert!(
                !script.contains("CimException"),
                "primary remove must not catch CimException (must let errors propagate): {script}"
            );
            assert!(
                !script.contains("try"),
                "primary remove must not wrap in try/catch (must let errors propagate): {script}"
            );
        }
    }

    mod self_referential {
        use super::*;

        #[test]
        fn gateway_with_server_as_address_is_self_referential() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                interface: "12".to_string(),
            };
            assert!(is_self_referential_next_hop(&server, &hop, 7));
        }

        #[test]
        fn gateway_on_tunnel_interface_is_self_referential() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "42".to_string(),
            };
            // Tunnel ifIndex is 42, same as the resolved route's interface.
            assert!(is_self_referential_next_hop(&server, &hop, 42));
        }

        #[test]
        fn onlink_on_tunnel_interface_is_self_referential() {
            let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "42".to_string(),
            };
            assert!(is_self_referential_next_hop(&server, &hop, 42));
        }

        #[test]
        fn gateway_via_real_router_on_other_interface_is_ok() {
            let server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "12".to_string(),
            };
            assert!(!is_self_referential_next_hop(&server, &hop, 42));
        }

        #[test]
        fn onlink_on_other_interface_is_ok() {
            let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
            let hop = NextHop::OnLink {
                interface: "12".to_string(),
            };
            assert!(!is_self_referential_next_hop(&server, &hop, 42));
        }

        #[test]
        fn ipv6_gateway_with_server_as_address_is_self_referential() {
            let server = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            let hop = NextHop::Gateway {
                address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                interface: "7".to_string(),
            };
            assert!(is_self_referential_next_hop(&server, &hop, 12));
        }
    }

    mod ps_escape {
        use super::*;

        #[test]
        fn plain_name_unchanged() {
            assert_eq!(escape_ps_single_quoted("Ethernet"), "Ethernet");
        }

        #[test]
        fn name_with_spaces_unchanged() {
            assert_eq!(escape_ps_single_quoted("Wi-Fi 2"), "Wi-Fi 2");
        }

        #[test]
        fn single_quote_is_doubled() {
            assert_eq!(escape_ps_single_quoted("Adapter'Name"), "Adapter''Name");
        }

        #[test]
        fn multiple_quotes_are_doubled() {
            assert_eq!(escape_ps_single_quoted("it's a 'test'"), "it''s a ''test''");
        }

        #[test]
        fn empty_string() {
            assert_eq!(escape_ps_single_quoted(""), "");
        }

        #[test]
        fn resolve_script_escapes_interface_name() {
            // Verify the composed script uses the escaped name, not the raw input.
            let name = "Adapter'Foo";
            let safe = escape_ps_single_quoted(name);
            let script = format!(
                "$ErrorActionPreference = 'Stop'; (Get-NetAdapter -Name '{}' -ErrorAction Stop).ifIndex",
                safe
            );
            assert_eq!(
                script,
                "$ErrorActionPreference = 'Stop'; (Get-NetAdapter -Name 'Adapter''Foo' -ErrorAction Stop).ifIndex"
            );
        }

        #[test]
        fn left_single_quotation_mark_escaped() {
            // U+2018 LEFT SINGLE QUOTATION MARK
            assert_eq!(
                escape_ps_single_quoted("Adapter\u{2018}Name"),
                "Adapter''Name"
            );
        }

        #[test]
        fn right_single_quotation_mark_escaped() {
            // U+2019 RIGHT SINGLE QUOTATION MARK
            assert_eq!(
                escape_ps_single_quoted("Adapter\u{2019}Name"),
                "Adapter''Name"
            );
        }

        #[test]
        fn single_low_9_quotation_mark_escaped() {
            // U+201A SINGLE LOW-9 QUOTATION MARK
            assert_eq!(
                escape_ps_single_quoted("Adapter\u{201A}Name"),
                "Adapter''Name"
            );
        }

        #[test]
        fn single_high_reversed_9_quotation_mark_escaped() {
            // U+201B SINGLE HIGH-REVERSED-9 QUOTATION MARK
            assert_eq!(
                escape_ps_single_quoted("Adapter\u{201B}Name"),
                "Adapter''Name"
            );
        }

        #[test]
        fn mixed_ascii_and_smart_quotes_all_escaped() {
            // All five quote variants in one string.
            let input = "a'b\u{2018}c\u{2019}d\u{201A}e\u{201B}f";
            let escaped = escape_ps_single_quoted(input);
            assert_eq!(escaped, "a''b''c''d''e''f");
        }
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

    mod user_routes_script {
        use super::*;

        #[test]
        fn single_ipv4_route() {
            let networks = vec!["10.0.0.0/8".parse::<IpNet>().unwrap()];
            let gateway: IpAddr = "192.168.1.1".parse().unwrap();
            let script = build_user_routes_script(&networks, &gateway, 12);
            assert_eq!(
                script,
                "$ErrorActionPreference = 'Stop'; \
                 New-NetRoute -DestinationPrefix '10.0.0.0/8' -InterfaceIndex 12 -NextHop '192.168.1.1' -PolicyStore ActiveStore; "
            );
        }

        #[test]
        fn multiple_ipv4_routes() {
            let networks: Vec<IpNet> = vec![
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
            ];
            let gateway: IpAddr = "10.255.0.1".parse().unwrap();
            let script = build_user_routes_script(&networks, &gateway, 42);
            assert!(script.starts_with("$ErrorActionPreference = 'Stop'; "));
            assert!(script.contains(
                "New-NetRoute -DestinationPrefix '10.0.0.0/8' -InterfaceIndex 42 -NextHop '10.255.0.1' -PolicyStore ActiveStore; "
            ));
            assert!(script.contains(
                "New-NetRoute -DestinationPrefix '172.16.0.0/12' -InterfaceIndex 42 -NextHop '10.255.0.1' -PolicyStore ActiveStore; "
            ));
            assert!(script.contains(
                "New-NetRoute -DestinationPrefix '192.168.0.0/16' -InterfaceIndex 42 -NextHop '10.255.0.1' -PolicyStore ActiveStore; "
            ));
        }

        #[test]
        fn ipv6_route() {
            let networks = vec!["2001:db8::/32".parse::<IpNet>().unwrap()];
            let gateway: IpAddr = "fe80::1".parse().unwrap();
            let script = build_user_routes_script(&networks, &gateway, 7);
            assert_eq!(
                script,
                "$ErrorActionPreference = 'Stop'; \
                 New-NetRoute -DestinationPrefix '2001:db8::/32' -InterfaceIndex 7 -NextHop 'fe80::1' -PolicyStore ActiveStore; "
            );
        }

        #[test]
        fn mixed_ipv4_and_ipv6_routes() {
            let networks: Vec<IpNet> = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
            let gateway: IpAddr = "10.0.0.1".parse().unwrap();
            let script = build_user_routes_script(&networks, &gateway, 5);
            assert!(script.contains(
                "New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex 5 -NextHop '10.0.0.1' -PolicyStore ActiveStore; "
            ));
            assert!(script.contains(
                "New-NetRoute -DestinationPrefix '::/0' -InterfaceIndex 5 -NextHop '10.0.0.1' -PolicyStore ActiveStore; "
            ));
        }

        #[test]
        fn empty_networks_produces_only_preamble() {
            let gateway: IpAddr = "10.0.0.1".parse().unwrap();
            let script = build_user_routes_script(&[], &gateway, 5);
            assert_eq!(script, "$ErrorActionPreference = 'Stop'; ");
        }
    }
}
