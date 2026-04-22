use std::net::IpAddr;

#[cfg(unix)]
mod posix;
#[cfg(unix)]
pub use posix::{add_routes, remove_exclusion_route};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{add_routes, remove_exclusion_route};

/// Represents the next-hop for reaching a destination address: either an IP
/// gateway or a directly-connected (on-link) interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextHop {
    /// Traffic is forwarded via a gateway router on the given interface.
    Gateway { address: IpAddr, interface: String },
    /// Traffic is delivered directly on the given interface (no gateway).
    OnLink { interface: String },
}

/// Token proving that an exclusion host-route was installed for the VPN
/// server's real IP address.  Carries all information needed to remove the
/// route on cleanup.
#[derive(Debug)]
pub struct InstalledExclusionRoute {
    pub destination: IpAddr,
    pub next_hop: NextHop,
}
