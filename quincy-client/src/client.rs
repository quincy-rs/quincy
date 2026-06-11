use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
#[cfg(all(unix, not(target_os = "macos")))]
use std::os::fd::RawFd;
use std::time::Duration;

use ipnet::IpNet;
use quinn::{Connection, Endpoint};
use tracing::{debug, info};

use quincy::config::ClientConfig;
use quincy::constants::QUINN_RUNTIME;
use quincy::error::ConfigError;
use quincy::ip_assignment;
#[cfg(all(unix, not(target_os = "macos")))]
use quincy::network::interface::tun_rs::TunRsInterface;
use quincy::network::interface::{Interface, InterfaceIO};
use quincy::network::socket::bind_socket;
use quincy::{QuincyError, Result};

use crate::relayer::ClientRelayer;

/// Default timeout for receiving IP assignment from server.
const IP_ASSIGNMENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Parameters available when creating the client-side tunnel interface.
#[derive(Clone, Debug)]
pub struct ClientInterfaceConfig {
    pub client_address: IpNet,
    pub server_address: IpNet,
    pub mtu: u16,
    pub tunnel_gateway: Option<IpAddr>,
    pub interface_name: Option<String>,
    pub routes: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
    pub remote_address: IpAddr,
}

/// Represents a Quincy client that connects to a server and relays packets between the server and a TUN interface.
pub struct QuincyClient {
    config: ClientConfig,
    relayer: Option<ClientRelayer>,
    client_address: Option<IpNet>,
    server_address: Option<IpNet>,
}

impl QuincyClient {
    /// Creates a new instance of a Quincy client.
    ///
    /// ### Arguments
    /// - `client_config` - the configuration for the client
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            relayer: None,
            client_address: None,
            server_address: None,
        }
    }

    /// Connects to the Quincy server and starts the workers for this instance of the Quincy client.
    ///
    /// Authentication happens during the QUIC handshake (Noise allowed-keys or TLS mTLS).
    /// After the handshake, the server sends the IP assignment over a uni-stream.
    pub async fn start<I: InterfaceIO>(&mut self) -> Result<()> {
        self.start_with_interface::<I, _>(|interface_config| {
            Interface::create(
                interface_config.client_address,
                interface_config.mtu,
                interface_config.tunnel_gateway,
                interface_config.interface_name,
                Some(interface_config.routes),
                Some(interface_config.dns_servers),
                Some(interface_config.remote_address),
            )
        })
        .await
    }

    /// Connects to the Quincy server and starts the client using a caller-created interface.
    ///
    /// This is intended for platforms where the system creates the TUN device
    /// and gives Quincy an existing handle, such as Android's VPN APIs.
    pub async fn start_with_interface<I, F>(&mut self, create_interface: F) -> Result<()>
    where
        I: InterfaceIO,
        F: FnOnce(ClientInterfaceConfig) -> Result<Interface<I>>,
    {
        if self.relayer.is_some() {
            return Err(QuincyError::system("Client is already started"));
        }

        let (connection, server_addr) = self.connect_to_server().await?;

        // Receive IP assignment from server (sent over uni-stream after handshake)
        let assignment =
            ip_assignment::recv_ip_assignment(&connection, IP_ASSIGNMENT_TIMEOUT).await?;

        let client_address = assignment.client_address;
        let server_address = assignment.server_address;

        info!("Received client address: {client_address}");
        info!("Received server address: {server_address}");

        // Store the addresses for later access
        self.client_address = Some(client_address);
        self.server_address = Some(server_address);

        let interface_config = ClientInterfaceConfig {
            client_address,
            server_address,
            mtu: self.config.connection.mtu,
            tunnel_gateway: Some(server_address.addr()),
            interface_name: self.config.network.interface_name.clone(),
            routes: self.config.network.routes.clone(),
            dns_servers: self.config.network.dns_servers.clone(),
            remote_address: server_addr.ip(),
        };

        let interface = create_interface(interface_config)?;

        let relayer = ClientRelayer::start(interface, connection)?;
        self.relayer.replace(relayer);

        Ok(())
    }

    /// Starts the client using an already-created TUN file descriptor.
    ///
    /// Intended for platforms such as Android where the system VPN API creates
    /// and configures the TUN device. The fd path therefore does not apply
    /// Quincy's route or DNS configuration; callers should configure those
    /// through the platform VPN API before passing the descriptor in.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid TUN file descriptor compatible with `tun-rs`, and
    /// the caller must not close or otherwise use it after ownership is passed
    /// to this function.
    #[cfg(all(unix, not(target_os = "macos")))]
    pub async unsafe fn start_with_tun_fd(&mut self, fd: RawFd) -> Result<()> {
        self.start_with_interface::<TunRsInterface, _>(|interface_config| {
            let interface = unsafe {
                TunRsInterface::from_fd(fd, interface_config.mtu, interface_config.tunnel_gateway)?
            };

            Ok(Interface::from_io(
                interface,
                None,
                None,
                Some(interface_config.remote_address),
            ))
        })
        .await
    }

    /// Returns whether the client is currently running.
    pub fn is_running(&self) -> bool {
        // TODO: this will return false if something else called `wait_for_shutdown`
        self.relayer.is_some()
    }

    /// Attempts to stop the client (if running).
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(relayer) = self.relayer.as_mut() {
            relayer.stop().await?;
        }

        // Clear stored addresses when stopping
        self.client_address = None;
        self.server_address = None;

        Ok(())
    }

    /// Waits for the client to stop relaying packets and finishes the shutdown process.
    pub async fn wait_for_shutdown(&mut self) -> Result<()> {
        if let Some(relayer) = self.relayer.take() {
            relayer.wait_for_shutdown().await?;
        }

        Ok(())
    }

    /// Returns a reference to the client relayer, if running.
    pub fn relayer(&self) -> Option<&ClientRelayer> {
        self.relayer.as_ref()
    }

    /// Returns the client IP address assigned during authentication.
    pub fn client_address(&self) -> Option<IpNet> {
        self.client_address
    }

    /// Returns the server IP address assigned during authentication.
    pub fn server_address(&self) -> Option<IpNet> {
        self.server_address
    }

    /// Connects to the Quincy server.
    ///
    /// ### Returns
    /// A tuple of the Quinn connection and the resolved server socket address.
    async fn connect_to_server(&self) -> Result<(Connection, SocketAddr)> {
        let quinn_config = self.config.quinn_client_config()?;

        let (host_part, _port) =
            self.config
                .connection_string
                .rsplit_once(':')
                .ok_or_else(|| {
                    QuincyError::Config(ConfigError::InvalidValue {
                        field: "connection_string".to_string(),
                        reason: format!(
                            "expected 'host:port' format, got '{}'",
                            self.config.connection_string
                        ),
                    })
                })?;

        // Strip brackets from IPv6 addresses (e.g., "[::1]" -> "::1")
        let server_hostname = host_part
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host_part);

        let server_addr = self
            .config
            .connection_string
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                QuincyError::connection_failed(format!(
                    "Connection string '{}' is invalid",
                    self.config.connection_string
                ))
            })?;

        info!("Connecting: {}", self.config.connection_string);

        let endpoint = self.create_quinn_endpoint(server_addr)?;
        let connection = endpoint
            .connect_with(quinn_config, server_addr, server_hostname)?
            .await?;

        info!("Connection established: {}", self.config.connection_string);

        Ok((connection, server_addr))
    }

    /// Creates a Quinn endpoint.
    ///
    /// ### Arguments
    /// - `remote_address` - the remote address to connect to
    ///
    /// ### Returns
    /// - `Endpoint` - the Quinn endpoint
    fn create_quinn_endpoint(&self, remote_address: SocketAddr) -> Result<Endpoint> {
        let bind_addr: SocketAddr = SocketAddr::new(
            match remote_address.ip() {
                IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
                IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
            },
            0,
        );
        debug!("QUIC socket local address: {:?}", bind_addr);

        let socket = bind_socket(
            bind_addr,
            self.config.connection.send_buffer_size as usize,
            self.config.connection.recv_buffer_size as usize,
            false,
        )?;

        let endpoint_config = self
            .config
            .connection
            .as_endpoint_config(self.config.noise_key_exchange())?;
        let endpoint = Endpoint::new(endpoint_config, None, socket, QUINN_RUNTIME.clone())?;

        Ok(endpoint)
    }
}
