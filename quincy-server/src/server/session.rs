//! User session registry for tracking active VPN connections.
//!
//! Provides a centralized, thread-safe registry that maps usernames to their
//! active connection sessions and shared rate limiters. The registry is only
//! accessed on connect/disconnect -- it is NOT in the packet forwarding hot path.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use ipnet::IpNet;
use tracing::info;

use quincy::config::Bandwidth;

/// Type alias for the governor rate limiter used for bandwidth limiting.
pub type BandwidthLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Metadata for a single active QUIC connection.
pub struct ConnectionSession {
    /// Tunnel IP assigned to this connection.
    pub client_address: IpNet,
    /// When this connection was established.
    pub connected_at: Instant,
}

/// Per-user state, potentially spanning multiple concurrent connections.
pub struct UserSession {
    /// All active connections for this user.
    connections: Vec<ConnectionSession>,
    /// Shared rate limiter across all connections and directions.
    /// `None` means unlimited bandwidth.
    rate_limiter: Option<Arc<BandwidthLimiter>>,
}

/// Thread-safe registry of active user sessions.
pub struct UserSessionRegistry {
    sessions: DashMap<String, UserSession>,
}

impl Default for UserSessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UserSessionRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    /// Registers a new connection for the given user.
    ///
    /// On the user's first connection, creates a new `UserSession` and
    /// optionally a rate limiter (if `bandwidth_limit` is `Some`). On
    /// subsequent connections, the new connection joins the existing session
    /// and shares the existing rate limiter.
    ///
    /// ### Arguments
    /// - `username` - the authenticated username
    /// - `session` - metadata for this connection
    /// - `bandwidth_limit` - effective bandwidth limit for this user
    ///
    /// ### Returns
    /// A cloned `Arc<BandwidthLimiter>` if the user has a bandwidth limit,
    /// or `None` if the user has unlimited bandwidth.
    pub fn add_connection(
        &self,
        username: &str,
        session: ConnectionSession,
        bandwidth_limit: Option<Bandwidth>,
    ) -> Option<Arc<BandwidthLimiter>> {
        let mut entry = self
            .sessions
            .entry(username.to_string())
            .or_insert_with(|| {
                let rate_limiter = bandwidth_limit.map(|bw| {
                    let kib_per_sec = bw.kib_per_second();
                    // kib_per_second() guarantees >= 1
                    let rate = NonZeroU32::new(kib_per_sec).expect("kib_per_second returns >= 1");
                    // Burst: at least 64 KiB or per-second rate, whichever is larger
                    let burst = NonZeroU32::new(kib_per_sec.max(64)).expect("burst is >= 64");
                    let quota = Quota::per_second(rate).allow_burst(burst);
                    Arc::new(RateLimiter::direct(quota))
                });

                info!(
                    "Created new session for user '{username}' (bandwidth limit: {})",
                    bandwidth_limit
                        .map(|bw| bw.to_string())
                        .unwrap_or_else(|| "unlimited".to_string())
                );

                UserSession {
                    connections: Vec::new(),
                    rate_limiter,
                }
            });

        entry.connections.push(session);
        entry.rate_limiter.clone()
    }

    /// Removes a specific connection for the given user, identified by its
    /// assigned tunnel IP address.
    ///
    /// If this was the user's last active connection, the entire `UserSession`
    /// (including the rate limiter) is dropped.
    pub fn remove_connection(&self, username: &str, client_address: &IpNet) {
        if self
            .sessions
            .remove_if_mut(username, |_, session| {
                session
                    .connections
                    .retain(|c| &c.client_address != client_address);
                session.connections.is_empty()
            })
            .is_some()
        {
            info!("Removed last session for user '{username}'");
        }
    }

    /// Returns the total number of active connections across all users.
    pub fn active_connection_count(&self) -> usize {
        self.sessions.iter().map(|e| e.connections.len()).sum()
    }

    /// Returns the number of users with at least one active connection.
    pub fn active_user_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use ipnet::IpNet;

    use quincy::config::Bandwidth;

    use super::{ConnectionSession, UserSessionRegistry};

    /// Helper to create a `ConnectionSession` with the given IP string.
    fn make_session(ip: &str) -> ConnectionSession {
        ConnectionSession {
            client_address: ip.parse().unwrap(),
            connected_at: Instant::now(),
        }
    }

    #[test]
    fn add_first_connection_creates_session() {
        let registry = UserSessionRegistry::new();
        registry.add_connection("alice", make_session("10.0.0.2/24"), None);

        assert_eq!(registry.active_connection_count(), 1);
        assert_eq!(registry.active_user_count(), 1);
    }

    #[test]
    fn add_second_connection_shares_limiter() {
        let registry = UserSessionRegistry::new();
        let bw = Some(Bandwidth::from_bytes_per_second(1_250_000));

        let limiter1 = registry.add_connection("alice", make_session("10.0.0.2/24"), bw);
        let limiter2 = registry.add_connection("alice", make_session("10.0.0.3/24"), bw);

        assert!(limiter1.is_some());
        assert!(limiter2.is_some());
        assert!(Arc::ptr_eq(
            limiter1.as_ref().unwrap(),
            limiter2.as_ref().unwrap()
        ));

        assert_eq!(registry.active_connection_count(), 2);
        assert_eq!(registry.active_user_count(), 1);
    }

    #[test]
    fn add_connection_unlimited() {
        let registry = UserSessionRegistry::new();
        let limiter = registry.add_connection("bob", make_session("10.0.0.4/24"), None);

        assert!(limiter.is_none());
    }

    #[test]
    fn remove_last_connection_drops_session() {
        let registry = UserSessionRegistry::new();
        let addr: IpNet = "10.0.0.2/24".parse().unwrap();

        registry.add_connection("alice", make_session("10.0.0.2/24"), None);
        assert_eq!(registry.active_connection_count(), 1);

        registry.remove_connection("alice", &addr);
        assert_eq!(registry.active_connection_count(), 0);
        assert_eq!(registry.active_user_count(), 0);
    }

    #[test]
    fn remove_one_of_two_connections() {
        let registry = UserSessionRegistry::new();
        let addr1: IpNet = "10.0.0.2/24".parse().unwrap();

        registry.add_connection("alice", make_session("10.0.0.2/24"), None);
        registry.add_connection("alice", make_session("10.0.0.3/24"), None);
        assert_eq!(registry.active_connection_count(), 2);

        registry.remove_connection("alice", &addr1);
        assert_eq!(registry.active_connection_count(), 1);
        assert_eq!(registry.active_user_count(), 1);
    }

    #[test]
    fn remove_nonexistent_connection_is_noop() {
        let registry = UserSessionRegistry::new();
        let addr: IpNet = "10.0.0.99/24".parse().unwrap();

        // Remove from unknown user — should not panic
        registry.remove_connection("nobody", &addr);

        // Remove unknown IP from existing user — should not panic
        registry.add_connection("alice", make_session("10.0.0.2/24"), None);
        registry.remove_connection("alice", &addr);

        assert_eq!(registry.active_connection_count(), 1);
    }

    #[tokio::test]
    async fn concurrent_add_remove() {
        let registry = Arc::new(UserSessionRegistry::new());
        let mut handles = Vec::new();

        for i in 0..20 {
            let registry = registry.clone();
            handles.push(tokio::spawn(async move {
                let ip = format!("10.0.{}.{}/24", i / 256, i % 256);
                let username = format!("user_{}", i % 5);
                let bw = if i % 2 == 0 {
                    Some(Bandwidth::from_bytes_per_second(1_000_000))
                } else {
                    None
                };

                registry.add_connection(&username, make_session(&ip), bw);

                // Yield to let other tasks interleave
                tokio::task::yield_now().await;

                let addr: IpNet = ip.parse().unwrap();
                registry.remove_connection(&username, &addr);
            }));
        }

        for handle in handles {
            handle.await.expect("task should not panic");
        }

        // All connections added and removed — counts should be zero
        assert_eq!(registry.active_connection_count(), 0);
        assert_eq!(registry.active_user_count(), 0);
    }
}
