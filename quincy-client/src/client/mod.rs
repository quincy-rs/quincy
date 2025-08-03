mod relayer;

use crate::auth::AuthClient;
use crate::users_file_auth::UsersFileClientAuthenticator;
use std::fmt::Debug;

use anyhow::{anyhow, Result};
use quincy::config::ClientConfig;
use quincy::constants::QUINN_RUNTIME;
use quincy::socket::bind_socket;
use quinn::{Connection, Endpoint};

use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use crate::client::relayer::ClientRelayer;
use quincy::network::interface::{Interface, InterfaceIO};
use tracing::{debug, info};

/// Represents a Quincy client that connects to a server and relays packets between the server and a TUN interface.
pub struct QuincyClient<I: InterfaceIO> {
    config: ClientConfig,
    relayer: Option<ClientRelayer<I>>,
    client_address: Option<IpNet>,
    server_address: Option<IpNet>,
}

impl<I: InterfaceIO> QuincyClient<I> {
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
    pub async fn start(&mut self) -> Result<()> {
        if self.relayer.is_some() {
            return Err(anyhow!("Client is already started"));
        }

        let connection = self.connect_to_server().await?;
        let authenticator = Box::new(UsersFileClientAuthenticator::new(
            &self.config.authentication,
        ));
        let auth_client = AuthClient::new(authenticator, self.config.connection.connection_timeout);

        let (client_address, server_address) = auth_client.authenticate(&connection).await?;

        info!("Successfully authenticated");
        info!("Received client address: {client_address}");
        info!("Received server address: {server_address}");

        // Store the addresses for later access
        self.client_address = Some(client_address);
        self.server_address = Some(server_address);

        let interface = Interface::create(
            client_address,
            self.config.connection.mtu,
            Some(server_address.addr()),
            Some(self.config.network.routes.clone()),
            Some(self.config.network.dns_servers.clone()),
        )?;

        let relayer = ClientRelayer::start(interface, connection)?;
        self.relayer.replace(relayer);

        Ok(())
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

    pub fn relayer(&self) -> Option<&ClientRelayer<I>> {
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
    /// - `Connection` - a Quinn connection representing the connection to the Quincy server
    async fn connect_to_server(&self) -> Result<Connection> {
        let quinn_config = self.config.quinn_client_config()?;

        let server_hostname = self
            .config
            .connection_string
            .split(':')
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "Could not parse hostname from connection string '{}'",
                    self.config.connection_string
                )
            })?;

        let server_addr = self
            .config
            .connection_string
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "Connection string '{}' is invalid",
                    self.config.connection_string
                )
            })?;

        info!("Connecting: {}", self.config.connection_string);

        let endpoint = self.create_quinn_endpoint(server_addr)?;
        let connection = endpoint
            .connect_with(quinn_config, server_addr, server_hostname)?
            .await?;

        info!("Connection established: {}", self.config.connection_string);

        Ok(connection)
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

        let endpoint_config = self.config.connection.as_endpoint_config()?;
        let endpoint = Endpoint::new(endpoint_config, None, socket, QUINN_RUNTIME.clone())?;

        Ok(endpoint)
    }
}

impl<I: InterfaceIO> Debug for QuincyClient<I> {
    // TODO: Implement a more detailed display format if needed
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QuincyClient ({})", self.config.connection_string)
    }
}
