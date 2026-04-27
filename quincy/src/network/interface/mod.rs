#![allow(async_fn_in_trait)]

pub mod tun_rs;

use crate::Result;
use crate::network::packet::Packet;
use crate::network::route::{InstalledExclusionRoute, remove_exclusion_route};
use ipnet::IpNet;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::error;

/// RAII guard that removes an installed exclusion host-route on drop.
///
/// Cleanup is best-effort: failures are logged at `error` level but not
/// propagated. The guard is armed when constructed with a `Some` exclusion
/// token and disarmed (no-op on drop) when constructed with `None`.
struct RouteGuard<I: InterfaceIO> {
    inner: Arc<I>,
    #[allow(unused)]
    routes: Option<Vec<IpNet>>,
    exclusion: Option<InstalledExclusionRoute>,
}

impl<I: InterfaceIO> RouteGuard<I> {
    /// Installs the tunnel routes and arms the guard with any resulting
    /// exclusion host-route token.
    fn configure(
        inner: Arc<I>,
        routes: Option<Vec<IpNet>>,
        remote_address: Option<IpAddr>,
    ) -> Result<Self> {
        let mut guard = Self {
            inner,
            routes,
            exclusion: None,
        };

        guard.exclusion = match &guard.routes {
            Some(routes) if !routes.is_empty() => {
                guard.inner.configure_routes(routes, remote_address)?
            }
            _ => None,
        };

        Ok(guard)
    }
}

impl<I: InterfaceIO> Drop for RouteGuard<I> {
    fn drop(&mut self) {
        if let Some(exclusion) = &self.exclusion {
            if let Err(e) = self.inner.remove_exclusion_route(exclusion) {
                error!(
                    "Failed to remove exclusion route for {}: {e}",
                    exclusion.destination
                );
            }
        }
    }
}

/// RAII guard that cleans up DNS configuration on drop.
///
/// Cleanup is best-effort: failures are logged at `error` level but not
/// propagated. The guard is armed when constructed with a `Some` DNS server
/// list and disarmed (no-op on drop) when constructed with `None`.
struct DnsGuard<I: InterfaceIO> {
    inner: Arc<I>,
    dns_servers: Option<Vec<IpAddr>>,
}

impl<I: InterfaceIO> DnsGuard<I> {
    /// Installs DNS configuration for the servers already stored in the guard.
    fn configure(inner: Arc<I>, dns_servers: Option<Vec<IpAddr>>) -> Result<Self> {
        let guard = Self { inner, dns_servers };

        let dns_servers = guard.dns_servers.as_deref().unwrap_or_default();

        if !dns_servers.is_empty() {
            guard.inner.configure_dns(dns_servers)?;
        }

        Ok(guard)
    }
}

impl<I: InterfaceIO> Drop for DnsGuard<I> {
    fn drop(&mut self) {
        let dns_servers = self.dns_servers.as_deref().unwrap_or_default();

        if !dns_servers.is_empty() {
            if let Err(e) = self.inner.cleanup_dns(dns_servers) {
                error!("Failed to cleanup DNS servers: {e}");
            }
        }
    }
}

pub trait InterfaceIO: Send + Sync + 'static {
    /// Creates a new interface with the specified parameters.
    fn create_interface(
        interface_address: IpNet,
        mtu: u16,
        tunnel_gateway: Option<IpAddr>,
        interface_name: Option<&str>,
    ) -> Result<Self>
    where
        Self: Sized;

    /// Configures the runtime routes for the interface.
    ///
    /// When `remote_address` is provided and the routes cover the default
    /// gateway, an exclusion host-route is installed for the server's real
    /// IP so tunnel traffic is not routed back into the tunnel.
    fn configure_routes(
        &self,
        routes: &[IpNet],
        remote_address: Option<IpAddr>,
    ) -> Result<Option<InstalledExclusionRoute>>;

    /// Configures the runtime DNS servers for the interface.
    fn configure_dns(&self, dns_servers: &[IpAddr]) -> Result<()>;

    /// Removes a previously-installed exclusion host-route.
    ///
    /// Default implementation delegates to the platform
    /// [`remove_exclusion_route`] helper. Exists as a trait method so test
    /// doubles can observe rollback without invoking platform commands.
    fn remove_exclusion_route(&self, exclusion: &InstalledExclusionRoute) -> Result<()> {
        remove_exclusion_route(exclusion)
    }

    /// Cleans up runtime configuration of DNS servers.
    fn cleanup_dns(&self, dns_servers: &[IpAddr]) -> Result<()>;

    /// Brings the interface down.
    fn down(&self) -> Result<()>;

    /// Returns the MTU (Maximum Transmission Unit) of the interface.
    fn mtu(&self) -> u16;

    /// Returns the name of the interface.
    fn name(&self) -> Option<String>;

    /// Reads a packet from the interface.
    fn read_packet(&self) -> impl Future<Output = Result<Packet>> + Send;

    /// Reads multiple packets from the interface.
    #[inline]
    fn read_packets(&self) -> impl Future<Output = Result<Vec<Packet>>> + Send {
        async move { Ok(vec![self.read_packet().await?]) }
    }

    /// Writes a packet to the interface.
    fn write_packet(&self, packet: Packet) -> impl Future<Output = Result<()>> + Send;

    /// Writes multiple packets to the interface.
    #[inline]
    fn write_packets(&self, packets: Vec<Packet>) -> impl Future<Output = Result<()>> + Send {
        async move {
            for packet in packets {
                self.write_packet(packet).await?;
            }
            Ok(())
        }
    }
}

/// An unconfigured TUN interface.
///
/// Holds the raw interface handle and deferred configuration (routes, DNS).
/// Call [`Interface::configure`] to apply runtime configuration and transition
/// into an [`ActiveInterface`] that owns packet I/O and cleanup.
pub struct Interface<I: InterfaceIO> {
    inner: I,
    routes: Option<Vec<IpNet>>,
    dns_servers: Option<Vec<IpAddr>>,
    remote_address: Option<IpAddr>,
}

impl<I: InterfaceIO> Interface<I> {
    pub fn create(
        interface_address: IpNet,
        mtu: u16,
        tunnel_gateway: Option<IpAddr>,
        interface_name: Option<String>,
        routes: Option<Vec<IpNet>>,
        dns_servers: Option<Vec<IpAddr>>,
        remote_address: Option<IpAddr>,
    ) -> Result<Self> {
        let interface = I::create_interface(
            interface_address,
            mtu,
            tunnel_gateway,
            interface_name.as_deref(),
        )?;

        Ok(Interface {
            inner: interface,
            routes,
            dns_servers,
            remote_address,
        })
    }

    /// Applies deferred route and DNS configuration, consuming this
    /// `Interface` and returning an [`ActiveInterface`] that owns packet
    /// I/O and cleanup.
    ///
    /// Guards are used for RAII-style rollback: if DNS configuration fails,
    /// the route guard and DNS guard are dropped automatically, cleaning up
    /// the exclusion route and any partial DNS state before the error is
    /// returned. On success, the armed guards are moved into `ActiveInterface`,
    /// which owns them for the full active lifetime and drops them in order
    /// (route → DNS) before bringing the interface down.
    pub fn configure(self) -> Result<ActiveInterface<I>> {
        let inner = Arc::new(self.inner);

        let route_guard = RouteGuard::configure(inner.clone(), self.routes, self.remote_address)?;
        let dns_guard = DnsGuard::configure(inner.clone(), self.dns_servers)?;

        Ok(ActiveInterface {
            inner,
            route_guard: Some(route_guard),
            dns_guard: Some(dns_guard),
        })
    }

    pub fn mtu(&self) -> u16 {
        self.inner.mtu()
    }
}

/// A configured, active TUN interface that owns packet I/O and cleanup.
///
/// Created by [`Interface::configure`]. On drop, the route guard is dropped
/// first (removing the exclusion host-route), then the DNS guard (cleaning up
/// DNS configuration), and finally the underlying device is brought down.
/// Ordinary tunnel routes are handled by system/interface teardown and are not
/// explicitly cleaned up here.
pub struct ActiveInterface<I: InterfaceIO> {
    inner: Arc<I>,
    route_guard: Option<RouteGuard<I>>,
    dns_guard: Option<DnsGuard<I>>,
}

impl<I: InterfaceIO> ActiveInterface<I> {
    pub fn mtu(&self) -> u16 {
        self.inner.mtu()
    }

    #[inline]
    pub async fn read_packet(&self) -> Result<Packet> {
        self.inner.read_packet().await
    }

    #[inline]
    pub async fn read_packets(&self) -> Result<Vec<Packet>> {
        self.inner.read_packets().await
    }

    #[inline]
    pub async fn write_packet(&self, packet: Packet) -> Result<()> {
        self.inner.write_packet(packet).await
    }

    #[inline]
    pub async fn write_packets(&self, packets: Vec<Packet>) -> Result<()> {
        self.inner.write_packets(packets).await
    }
}

impl<I: InterfaceIO> Drop for ActiveInterface<I> {
    fn drop(&mut self) {
        // Drop guards first to ensure routes and DNS are cleaned up
        // before the interface is brought down.
        drop(self.route_guard.take());
        drop(self.dns_guard.take());

        if let Err(e) = self.inner.down() {
            error!("Failed to bring down TUN interface: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::InterfaceError;
    use crate::network::route::NextHop;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// In-process double that records calls and can be told which ones should
    /// fail. Covers the `configure` rollback paths and `ActiveInterface::Drop`
    /// sequencing without touching platform `route`/DNS commands.
    ///
    /// Wrapped in `Arc` and adapted to `InterfaceIO` through [`SharedMock`] so
    /// tests can inspect counters after the value is moved into `Interface` or
    /// `ActiveInterface`.
    #[derive(Default)]
    struct MockInterface {
        configure_routes_calls: AtomicUsize,
        configure_dns_calls: AtomicUsize,
        remove_exclusion_calls: AtomicUsize,
        cleanup_dns_calls: AtomicUsize,
        down_calls: AtomicUsize,

        fail_configure_routes: AtomicBool,
        fail_configure_dns: AtomicBool,
        fail_remove_exclusion: AtomicBool,
        fail_cleanup_dns: AtomicBool,

        /// When set, `configure_routes` returns this exclusion token on success.
        exclusion_token: std::sync::Mutex<Option<InstalledExclusionRoute>>,
    }

    fn configuration_failed(reason: &str) -> crate::QuincyError {
        InterfaceError::ConfigurationFailed {
            reason: reason.to_string(),
        }
        .into()
    }

    fn sample_exclusion() -> InstalledExclusionRoute {
        InstalledExclusionRoute {
            destination: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            next_hop: NextHop::OnLink {
                interface: "test0".to_string(),
            },
        }
    }

    /// Thin newtype that lets tests observe the shared mock state after
    /// ownership has been transferred into `Interface`/`ActiveInterface`.
    struct SharedMock(Arc<MockInterface>);

    impl InterfaceIO for SharedMock {
        fn create_interface(
            _interface_address: IpNet,
            _mtu: u16,
            _tunnel_gateway: Option<IpAddr>,
            _interface_name: Option<&str>,
        ) -> Result<Self> {
            unreachable!("SharedMock is only constructed manually in tests")
        }

        fn configure_routes(
            &self,
            _routes: &[IpNet],
            _remote_address: Option<IpAddr>,
        ) -> Result<Option<InstalledExclusionRoute>> {
            self.0.configure_routes_calls.fetch_add(1, Ordering::SeqCst);

            if self.0.fail_configure_routes.load(Ordering::SeqCst) {
                return Err(configuration_failed("forced configure_routes failure"));
            }

            Ok(self.0.exclusion_token.lock().unwrap().take())
        }

        fn configure_dns(&self, _dns_servers: &[IpAddr]) -> Result<()> {
            self.0.configure_dns_calls.fetch_add(1, Ordering::SeqCst);

            if self.0.fail_configure_dns.load(Ordering::SeqCst) {
                return Err(configuration_failed("forced configure_dns failure"));
            }

            Ok(())
        }

        fn remove_exclusion_route(&self, _exclusion: &InstalledExclusionRoute) -> Result<()> {
            self.0.remove_exclusion_calls.fetch_add(1, Ordering::SeqCst);

            if self.0.fail_remove_exclusion.load(Ordering::SeqCst) {
                return Err(configuration_failed(
                    "forced remove_exclusion_route failure",
                ));
            }

            Ok(())
        }

        fn cleanup_dns(&self, _dns_servers: &[IpAddr]) -> Result<()> {
            self.0.cleanup_dns_calls.fetch_add(1, Ordering::SeqCst);

            if self.0.fail_cleanup_dns.load(Ordering::SeqCst) {
                return Err(configuration_failed("forced cleanup_dns failure"));
            }

            Ok(())
        }

        fn down(&self) -> Result<()> {
            self.0.down_calls.fetch_add(1, Ordering::SeqCst);

            Ok(())
        }

        fn mtu(&self) -> u16 {
            1400
        }

        fn name(&self) -> Option<String> {
            Some("mock".to_string())
        }

        async fn read_packet(&self) -> Result<Packet> {
            unreachable!("mock interface does not perform I/O in these tests")
        }

        async fn write_packet(&self, _packet: Packet) -> Result<()> {
            unreachable!("mock interface does not perform I/O in these tests")
        }
    }

    /// Builds a shared mock, lets the test seed failure flags and tokens, then
    /// drives `Interface::configure` through to its error path.
    fn configure_with_shared_mock(
        seed: impl FnOnce(&MockInterface),
    ) -> (crate::QuincyError, Arc<MockInterface>) {
        let mock = Arc::new(MockInterface::default());
        seed(&mock);

        let interface = Interface {
            inner: SharedMock(mock.clone()),
            routes: Some(vec!["0.0.0.0/0".parse().unwrap()]),
            dns_servers: Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]),
            remote_address: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        };

        // `expect_err` requires `T: Debug`; `ActiveInterface` deliberately
        // does not implement `Debug`, so match the Result directly.
        let err = match interface.configure() {
            Ok(_) => panic!("configure must fail"),
            Err(e) => e,
        };

        (err, mock)
    }

    #[test]
    fn configure_routes_failure_skips_all_later_steps() {
        let (err, mock) = configure_with_shared_mock(|mock| {
            mock.fail_configure_routes.store(true, Ordering::SeqCst);
        });

        assert!(matches!(
            err,
            crate::QuincyError::Interface(InterfaceError::ConfigurationFailed { .. })
        ));

        assert_eq!(mock.configure_routes_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            mock.configure_dns_calls.load(Ordering::SeqCst),
            0,
            "DNS must not be configured when route configuration fails"
        );
        assert_eq!(
            mock.remove_exclusion_calls.load(Ordering::SeqCst),
            0,
            "no exclusion token was produced, so nothing to remove"
        );
        assert_eq!(mock.cleanup_dns_calls.load(Ordering::SeqCst), 0);
        assert_eq!(mock.down_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dns_failure_with_exclusion_removes_exclusion_and_cleans_dns() {
        let (_err, mock) = configure_with_shared_mock(|mock| {
            *mock.exclusion_token.lock().unwrap() = Some(sample_exclusion());
            mock.fail_configure_dns.store(true, Ordering::SeqCst);
        });

        assert_eq!(mock.configure_routes_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.configure_dns_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            mock.remove_exclusion_calls.load(Ordering::SeqCst),
            1,
            "exclusion route must be removed on DNS-failure rollback"
        );
        assert_eq!(
            mock.cleanup_dns_calls.load(Ordering::SeqCst),
            1,
            "partial DNS state must be cleaned up on DNS-failure rollback"
        );
        // ActiveInterface was never constructed, so its Drop must not fire.
        assert_eq!(mock.down_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dns_failure_without_exclusion_still_cleans_dns() {
        let (_err, mock) = configure_with_shared_mock(|mock| {
            // No exclusion token seeded → configure_routes returns Ok(None).
            mock.fail_configure_dns.store(true, Ordering::SeqCst);
        });

        assert_eq!(mock.configure_routes_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.configure_dns_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            mock.remove_exclusion_calls.load(Ordering::SeqCst),
            0,
            "no exclusion token was installed, so nothing to remove"
        );
        assert_eq!(
            mock.cleanup_dns_calls.load(Ordering::SeqCst),
            1,
            "DNS cleanup still runs to undo any partial state"
        );
        assert_eq!(mock.down_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn active_interface_drop_continues_after_earlier_cleanup_failure() {
        let mock = Arc::new(MockInterface::default());
        *mock.exclusion_token.lock().unwrap() = Some(sample_exclusion());
        mock.fail_remove_exclusion.store(true, Ordering::SeqCst);

        let inner = Arc::new(SharedMock(mock.clone()));
        let active = ActiveInterface {
            route_guard: Some(
                RouteGuard::configure(
                    inner.clone(),
                    Some(vec!["0.0.0.0/0".parse().unwrap()]),
                    Some("12.13.14.15".parse().unwrap()),
                )
                .unwrap(),
            ),
            dns_guard: Some(
                DnsGuard::configure(
                    inner.clone(),
                    Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]),
                )
                .unwrap(),
            ),
            inner,
        };

        drop(active);

        // Every best-effort cleanup step must have been attempted exactly once,
        // even though the earlier exclusion removal failed.
        assert_eq!(mock.remove_exclusion_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.cleanup_dns_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.down_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn successful_configure_does_not_run_cleanup_and_disarms_guards() {
        let mock = Arc::new(MockInterface::default());
        *mock.exclusion_token.lock().unwrap() = Some(sample_exclusion());

        let interface = Interface {
            inner: SharedMock(mock.clone()),
            routes: Some(vec!["0.0.0.0/0".parse().unwrap()]),
            dns_servers: Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]),
            remote_address: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        };

        let active = interface.configure().expect("configure must succeed");

        // Guards were disarmed — no cleanup should have run during configure.
        assert_eq!(mock.configure_routes_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock.configure_dns_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            mock.remove_exclusion_calls.load(Ordering::SeqCst),
            0,
            "exclusion route must not be removed during successful configure"
        );
        assert_eq!(
            mock.cleanup_dns_calls.load(Ordering::SeqCst),
            0,
            "DNS must not be cleaned up during successful configure"
        );
        assert_eq!(mock.down_calls.load(Ordering::SeqCst), 0);

        // Now drop the active interface and verify cleanup runs exactly once.
        drop(active);

        assert_eq!(
            mock.remove_exclusion_calls.load(Ordering::SeqCst),
            1,
            "exclusion route must be removed when ActiveInterface is dropped"
        );
        assert_eq!(
            mock.cleanup_dns_calls.load(Ordering::SeqCst),
            1,
            "DNS must be cleaned up when ActiveInterface is dropped"
        );
        assert_eq!(mock.down_calls.load(Ordering::SeqCst), 1);
    }
}
