use anyhow::Result;
use std::net::IpAddr;
use wintun_bindings::Adapter;

/// Adds a list of DNS servers to all network services on the endpoint.
///
/// ### Arguments
/// - `dns_servers` - the DNS servers to be added
/// - `interface_name` - the name of the interface to add the DNS servers to (unused)
pub fn add_dns_servers(dns_servers: &[IpAddr], interface_name: &str) -> Result<()> {
    let wintun = unsafe {
        // SAFETY: signature verification is enabled in the WinTun library
        wintun_bindings::load()?
    };

    let adapter = Adapter::open(&wintun, interface_name)?;
    adapter.set_dns_servers(dns_servers)?;

    Ok(())
}

/// Deletes all DNS servers from the given interface.
///
/// No-op on Windows.
pub fn delete_dns_servers() -> anyhow::Result<()> {
    // This is a no-op on Windows as the interface is deleted when the process exits
    // along with its routes and DNS servers
    Ok(())
}
