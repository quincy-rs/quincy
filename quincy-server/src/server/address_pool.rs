use std::collections::HashMap;
use std::net::IpAddr;

use dashmap::DashSet;
use ipnet::IpNet;

use quincy::config::AddressRange;
use quincy::error::{AuthError, Result};

/// A pool of IP addresses from which addresses can be allocated and released.
///
/// Stores address ranges lazily and iterates them on each allocation,
/// avoiding materialization of the full address list into memory.
pub struct AddressPool {
    /// The ranges this pool can allocate from, scanned in order.
    ranges: Vec<AddressRange>,
    /// Addresses currently allocated or reserved.
    used_addresses: DashSet<IpAddr>,
}

impl AddressPool {
    /// Creates a new pool from the given address ranges.
    ///
    /// ### Arguments
    /// - `ranges` - the address ranges this pool can allocate from
    pub fn new(ranges: Vec<AddressRange>) -> Self {
        Self {
            ranges,
            used_addresses: DashSet::new(),
        }
    }

    /// Returns the next available address, or `None` if the pool is exhausted.
    ///
    /// Lazily scans all ranges and atomically claims the first unused address
    /// via [`DashSet::insert`], which returns `true` only if the address was
    /// not already present.
    pub fn next_available_address(&self) -> Option<IpAddr> {
        self.ranges
            .iter()
            .flat_map(|range| range.into_inner())
            .find(|address| self.used_addresses.insert(*address))
    }

    /// Releases the specified address so it can be allocated again.
    ///
    /// ### Arguments
    /// - `address` - the address to release
    pub fn release_address(&self, address: &IpAddr) {
        self.used_addresses.remove(address);
    }

    /// Marks a set of addresses as used, preventing them from being allocated.
    ///
    /// ### Arguments
    /// - `addresses` - the addresses to reserve
    pub fn reserve_addresses(&self, addresses: impl Iterator<Item = IpAddr>) {
        for address in addresses {
            self.used_addresses.insert(address);
        }
    }
}

/// Manages IP address allocation across a global pool and optional per-user
/// reserved pools.
///
/// Users with a per-user pool get addresses exclusively from their reserved set.
/// Users without a per-user pool get addresses from the global (unreserved) pool.
/// Reserved addresses are pre-inserted into the global pool's used set at
/// construction time so they are never handed out to unrestricted users.
pub struct AddressPoolManager {
    /// The tunnel network (carries server IP + netmask for wrapping allocations).
    network: IpNet,
    /// Pool of unreserved addresses available to any user.
    global_pool: AddressPool,
    /// Per-user reserved pools, keyed by username.
    user_pools: HashMap<String, AddressPool>,
}

impl AddressPoolManager {
    /// Creates a new address pool manager for the given tunnel network.
    ///
    /// The global pool covers the entire tunnel network with the network address,
    /// server address, and broadcast address pre-reserved. All addresses from
    /// per-user pools are also pre-reserved in the global pool.
    ///
    /// # Performance
    ///
    /// Every address in every per-user range is iterated eagerly for validation
    /// and reservation. Very large ranges (e.g. a `/8` with ~16 M addresses)
    /// will cause proportional memory and CPU usage at startup. Prefer narrow
    /// per-user ranges (a `/24` or smaller is typical).
    ///
    /// ### Arguments
    /// - `network` - the tunnel network (server IP + netmask)
    /// - `user_pools` - per-user address ranges, keyed by username
    ///
    /// ### Errors
    /// Returns `AuthError::InvalidUserStore` if any user pool address falls
    /// outside the tunnel network or is a reserved tunnel address (network,
    /// server, or broadcast).
    pub fn new(network: IpNet, user_pools: HashMap<String, Vec<AddressRange>>) -> Result<Self> {
        // Build the global pool covering the entire tunnel network
        let global_pool = AddressPool::new(vec![AddressRange::from(network)]);

        // Pre-reserve network, server, and broadcast addresses
        let reserved = [network.network(), network.addr(), network.broadcast()];
        global_pool.reserve_addresses(reserved.iter().copied());

        // Validate and build per-user pools
        let mut built_user_pools = HashMap::with_capacity(user_pools.len());

        for (username, ranges) in &user_pools {
            // Validate all addresses in the user's ranges are within the tunnel network
            // and are not reserved infrastructure addresses
            for range in ranges {
                for address in range.into_inner() {
                    if !network.contains(&address) {
                        return Err(AuthError::InvalidUserStore {
                            reason: format!(
                                "user '{username}': address {address} is outside \
                                 tunnel network {network}"
                            ),
                        }
                        .into());
                    }
                    if reserved.contains(&address) {
                        return Err(AuthError::InvalidUserStore {
                            reason: format!(
                                "user '{username}': address {address} is a reserved \
                                 tunnel address (network, server, or broadcast)"
                            ),
                        }
                        .into());
                    }
                }
            }

            // Pre-reserve user pool addresses in the global pool
            global_pool.reserve_addresses(ranges.iter().flat_map(|range| range.into_inner()));

            built_user_pools.insert(username.clone(), AddressPool::new(ranges.clone()));
        }

        Ok(Self {
            network,
            global_pool,
            user_pools: built_user_pools,
        })
    }

    /// Allocates an address for the given user.
    ///
    /// If the user has a per-user pool, allocates from that pool. Otherwise
    /// allocates from the global pool. Returns the address wrapped in an
    /// [`IpNet`] with the tunnel network's netmask.
    ///
    /// ### Arguments
    /// - `username` - the authenticated username
    pub fn allocate_address(&self, username: &str) -> Option<IpNet> {
        let address = match self.user_pools.get(username) {
            Some(user_pool) => user_pool.next_available_address()?,
            None => self.global_pool.next_available_address()?,
        };

        Some(
            IpNet::with_netmask(address, self.network.netmask())
                .expect("Netmask is always valid for addresses within the tunnel network"),
        )
    }

    /// Releases an address back to the appropriate pool.
    ///
    /// If the user has a per-user pool, releases to that pool. Otherwise
    /// releases to the global pool.
    ///
    /// ### Arguments
    /// - `username` - the authenticated username
    /// - `address` - the address to release
    pub fn release_address(&self, username: &str, address: &IpAddr) {
        match self.user_pools.get(username) {
            Some(user_pool) => user_pool.release_address(address),
            None => self.global_pool.release_address(address),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::{IpNet, Ipv4Net};
    use quincy::config::AddressRange;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    /// 10.0.0.0/29 = 8 addresses: .0 (network), .1 (server), .2-.6 (usable), .7 (broadcast)
    fn test_network() -> IpNet {
        IpNet::V4(
            Ipv4Net::with_netmask(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(255, 255, 255, 248),
            )
            .unwrap(),
        )
    }

    // --- AddressPool tests ---

    #[test]
    fn pool_allocates_in_order() {
        let ranges = vec!["10.0.0.2 - 10.0.0.4".parse::<AddressRange>().unwrap()];
        let pool = AddressPool::new(ranges);

        assert_eq!(
            pool.next_available_address(),
            Some(Ipv4Addr::new(10, 0, 0, 2).into())
        );
        assert_eq!(
            pool.next_available_address(),
            Some(Ipv4Addr::new(10, 0, 0, 3).into())
        );
        assert_eq!(
            pool.next_available_address(),
            Some(Ipv4Addr::new(10, 0, 0, 4).into())
        );
        assert_eq!(pool.next_available_address(), None);
    }

    #[test]
    fn pool_release_and_reallocate() {
        let ranges = vec!["10.0.0.2/32".parse::<AddressRange>().unwrap()];
        let pool = AddressPool::new(ranges);

        let addr = pool.next_available_address().unwrap();
        assert_eq!(pool.next_available_address(), None);

        pool.release_address(&addr);
        assert_eq!(pool.next_available_address(), Some(addr));
    }

    #[test]
    fn pool_reserve_addresses() {
        let ranges = vec!["10.0.0.2 - 10.0.0.4".parse::<AddressRange>().unwrap()];
        let pool = AddressPool::new(ranges);
        pool.reserve_addresses([Ipv4Addr::new(10, 0, 0, 3).into()].into_iter());

        assert_eq!(
            pool.next_available_address(),
            Some(Ipv4Addr::new(10, 0, 0, 2).into())
        );
        // .3 is reserved, skipped
        assert_eq!(
            pool.next_available_address(),
            Some(Ipv4Addr::new(10, 0, 0, 4).into())
        );
        assert_eq!(pool.next_available_address(), None);
    }

    // --- AddressPoolManager tests ---

    #[test]
    fn manager_global_pool_excludes_reserved() {
        let user_pools = HashMap::from([(
            "alice".to_string(),
            vec!["10.0.0.2/32".parse::<AddressRange>().unwrap()],
        )]);
        let manager = AddressPoolManager::new(test_network(), user_pools).unwrap();

        // Global pool should skip .0 (network), .1 (server), .2 (reserved), .7 (broadcast)
        // First global allocation is .3
        let addr = manager.allocate_address("bob").unwrap();
        assert_eq!(addr.addr(), IpAddr::from(Ipv4Addr::new(10, 0, 0, 3)));
    }

    #[test]
    fn manager_user_pool_allocates_from_reserved() {
        let user_pools = HashMap::from([(
            "alice".to_string(),
            vec!["10.0.0.5 - 10.0.0.6".parse::<AddressRange>().unwrap()],
        )]);
        let manager = AddressPoolManager::new(test_network(), user_pools).unwrap();

        let addr = manager.allocate_address("alice").unwrap();
        assert_eq!(addr.addr(), IpAddr::from(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn manager_user_pool_exhaustion() {
        let user_pools = HashMap::from([(
            "alice".to_string(),
            vec!["10.0.0.5/32".parse::<AddressRange>().unwrap()],
        )]);
        let manager = AddressPoolManager::new(test_network(), user_pools).unwrap();

        assert!(manager.allocate_address("alice").is_some());
        assert!(manager.allocate_address("alice").is_none());
        // Global pool still works for other users
        assert!(manager.allocate_address("bob").is_some());
    }

    #[test]
    fn manager_release_user_pool_and_reallocate() {
        let user_pools = HashMap::from([(
            "alice".to_string(),
            vec!["10.0.0.5/32".parse::<AddressRange>().unwrap()],
        )]);
        let manager = AddressPoolManager::new(test_network(), user_pools).unwrap();

        let addr = manager.allocate_address("alice").unwrap();
        assert!(manager.allocate_address("alice").is_none());

        manager.release_address("alice", &addr.addr());
        assert!(manager.allocate_address("alice").is_some());
    }

    #[test]
    fn manager_release_global_and_reallocate() {
        let manager = AddressPoolManager::new(test_network(), HashMap::new()).unwrap();

        let addr = manager.allocate_address("bob").unwrap();
        manager.release_address("bob", &addr.addr());

        let addr2 = manager.allocate_address("bob").unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn manager_rejects_user_pool_outside_network() {
        let user_pools = HashMap::from([(
            "alice".to_string(),
            vec!["192.168.1.1/32".parse::<AddressRange>().unwrap()],
        )]);
        let result = AddressPoolManager::new(test_network(), user_pools);
        assert!(result.is_err());
    }

    #[test]
    fn manager_no_user_pools() {
        let manager = AddressPoolManager::new(test_network(), HashMap::new()).unwrap();

        // Should get .2 through .6 (5 usable addresses)
        for expected in 2..=6u8 {
            let addr = manager.allocate_address("anyone").unwrap();
            assert_eq!(addr.addr(), IpAddr::from(Ipv4Addr::new(10, 0, 0, expected)));
        }
        assert!(manager.allocate_address("anyone").is_none());
    }

    #[test]
    fn manager_rejects_user_pool_with_network_address() {
        let user_pools = HashMap::from([(
            "alice".to_string(),
            vec!["10.0.0.0/32".parse::<AddressRange>().unwrap()],
        )]);
        let result = AddressPoolManager::new(test_network(), user_pools);
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("reserved tunnel address"), "error: {err}");
    }

    #[test]
    fn manager_rejects_user_pool_with_server_address() {
        let user_pools = HashMap::from([(
            "alice".to_string(),
            vec!["10.0.0.1/32".parse::<AddressRange>().unwrap()],
        )]);
        let result = AddressPoolManager::new(test_network(), user_pools);
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("reserved tunnel address"), "error: {err}");
    }

    #[test]
    fn manager_rejects_user_pool_with_broadcast_address() {
        let user_pools = HashMap::from([(
            "alice".to_string(),
            vec!["10.0.0.7/32".parse::<AddressRange>().unwrap()],
        )]);
        let result = AddressPoolManager::new(test_network(), user_pools);
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("reserved tunnel address"), "error: {err}");
    }

    #[test]
    fn manager_netmask_preserved() {
        let manager = AddressPoolManager::new(test_network(), HashMap::new()).unwrap();
        let addr = manager.allocate_address("bob").unwrap();
        assert_eq!(addr.netmask(), test_network().netmask());
    }
}
