pub mod address_pool;
mod connection;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::auth::server::AuthServer;
use crate::config::ServerConfig;
use crate::server::connection::QuincyConnection;
use crate::socket::bind_socket;
use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use quinn::{Endpoint, VarInt};
use tokio::signal;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use self::address_pool::AddressPool;
use crate::constants::{PACKET_BUFFER_SIZE, PACKET_CHANNEL_SIZE, QUINN_RUNTIME};
use crate::network::interface::{Interface, InterfaceIO};
use crate::network::packet::Packet;
use crate::utils::tasks::abort_all;
use tracing::{debug, info, warn};

type ConnectionQueues = Arc<DashMap<IpAddr, Sender<Bytes>>>;

/// Represents a Quincy server encapsulating Quincy connections and TUN interface IO.
pub struct QuincyServer {
    config: ServerConfig,
    connection_queues: ConnectionQueues,
    address_pool: Arc<AddressPool>,
}

impl QuincyServer {
    /// Creates a new instance of the Quincy tunnel.
    ///
    /// ### Arguments
    /// - `config` - the server configuration
    pub fn new(config: ServerConfig) -> Result<Self> {
        let address_pool = AddressPool::new(config.tunnel_network);

        Ok(Self {
            config,
            connection_queues: Arc::new(DashMap::new()),
            address_pool: Arc::new(address_pool),
        })
    }

    /// Starts the tasks for this instance of Quincy tunnel and listens for incoming connections.
    pub async fn run<I: InterfaceIO>(&self) -> Result<()> {
        let interface: Interface<I> = Interface::create(
            self.config.tunnel_network,
            self.config.connection.mtu,
            Some(self.config.tunnel_network.network()),
            None,
            None,
        )?;
        let interface = Arc::new(interface);

        let auth_server = AuthServer::new(
            self.config.authentication.clone(),
            self.config.tunnel_network,
            self.address_pool.clone(),
            self.config.connection.connection_timeout,
        )?;

        let (sender, receiver) = channel(PACKET_CHANNEL_SIZE);

        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(Self::process_outbound_traffic(
                interface.clone(),
                self.connection_queues.clone(),
            )),
            tokio::spawn(Self::process_inbound_traffic(
                self.connection_queues.clone(),
                interface,
                receiver,
                self.config.isolate_clients,
            )),
        ]);

        let handler_task = self.handle_connections(auth_server, sender);

        let result = tokio::select! {
            handler_task_result = handler_task => handler_task_result,
            Some(task_result) = tasks.next() => task_result?,
        };

        let _ = abort_all(tasks).await;

        result
    }

    /// Handles incoming connections by spawning a new QuincyConnection instance for them.
    ///
    /// ### Arguments
    /// - `auth_server` - the authentication server to use for authenticating clients
    /// - `ingress_queue` - the queue for sending data to the TUN interface
    async fn handle_connections(
        &self,
        auth_server: AuthServer,
        ingress_queue: Sender<Packet>,
    ) -> Result<()> {
        let endpoint = self.create_quinn_endpoint()?;

        info!(
            "Starting connection handler: {}",
            endpoint.local_addr().expect("Endpoint has a local address")
        );

        let mut authentication_tasks = FuturesUnordered::new();
        let mut connection_tasks = FuturesUnordered::new();

        loop {
            tokio::select! {
                // New connections
                Some(handshake) = endpoint.accept() => {
                    let client_ip = handshake.remote_address().ip();

                    debug!(
                        "Received incoming connection from '{}'",
                        client_ip
                    );

                    let quic_connection = match handshake.await {
                        Ok(connection) => connection,
                        Err(e) => {
                            warn!("Connection handshake with client '{client_ip}' failed: {e}");
                            continue;
                        }
                    };

                    let connection = QuincyConnection::new(
                        quic_connection,
                        ingress_queue.clone(),
                    );

                    authentication_tasks.push(
                        connection.authenticate(&auth_server)
                    );
                }

                // Authentication tasks
                Some(connection) = authentication_tasks.next() => {
                    let connection = match connection {
                        Ok(connection) => connection,
                        Err(e) => {
                            warn!("Failed to authenticate client: {e}");
                            continue;
                        }
                    };

                    let client_address = connection.client_address()?.addr();
                    let (connection_sender, connection_receiver) = channel(PACKET_CHANNEL_SIZE);

                    connection_tasks.push(tokio::spawn(connection.run(connection_receiver)));
                    self.connection_queues.insert(client_address, connection_sender);
                }

                // Connection tasks
                Some(connection) = connection_tasks.next() => {
                    let (connection, err) = connection?;
                    let client_address = &connection.client_address()?.addr();

                    self.connection_queues.remove(client_address);
                    self.address_pool.release_address(client_address);
                    warn!("Connection with client {client_address} has encountered an error: {err}");
                }

                // Shutdown
                _ = signal::ctrl_c() => {
                    info!("Received shutdown signal, shutting down");
                    let _ = abort_all(connection_tasks).await;

                    endpoint.close(VarInt::from_u32(0x01), "Server shutdown".as_bytes());

                    return Ok(());
                }
            }
        }
    }

    /// Creates a Quinn QUIC endpoint that clients can connect to.
    fn create_quinn_endpoint(&self) -> Result<Endpoint> {
        let quinn_config = self.config.as_quinn_server_config()?;

        let socket = bind_socket(
            SocketAddr::new(self.config.bind_address, self.config.bind_port),
            self.config.connection.send_buffer_size as usize,
            self.config.connection.recv_buffer_size as usize,
            self.config.reuse_socket,
        )?;

        let endpoint_config = self.config.connection.as_endpoint_config()?;
        let endpoint = Endpoint::new(
            endpoint_config,
            Some(quinn_config),
            socket,
            QUINN_RUNTIME.clone(),
        )?;

        Ok(endpoint)
    }

    /// Reads data from the TUN interface and sends it to the appropriate client.
    ///
    /// ### Arguments
    /// - `tun_read` - the read half of the TUN interface
    /// - `connection_queues` - the queues for sending data to the QUIC connections
    /// - `buffer_size` - the size of the buffer to use when reading from the TUN interface
    async fn process_outbound_traffic(
        interface: Arc<Interface<impl InterfaceIO>>,
        connection_queues: ConnectionQueues,
    ) -> Result<()> {
        debug!("Started tunnel outbound traffic task (interface -> connection queue)");

        loop {
            let packet = interface.read_packet().await?;
            let dest_addr = match packet.destination() {
                Ok(addr) => addr,
                Err(e) => {
                    warn!("Received packet with malformed header structure: {e}");
                    continue;
                }
            };

            debug!("Destination address for packet: {dest_addr}");

            let connection_queue = match connection_queues.get(&dest_addr) {
                Some(connection_queue) => connection_queue,
                None => continue,
            };

            debug!("Found connection for IP {dest_addr}");

            connection_queue.send(packet.into()).await?;
        }
    }

    /// Reads data from the QUIC connection and sends it to the TUN interface worker.
    ///
    /// ### Arguments
    /// - `connection_queues` - the queues for sending data to the QUIC connections
    /// - `tun_write` - the write half of the TUN interface
    /// - `ingress_queue` - the queue for sending data to the TUN interface
    /// - `isolate_clients` - whether to isolate clients from each other
    async fn process_inbound_traffic(
        connection_queues: ConnectionQueues,
        interface: Arc<Interface<impl InterfaceIO>>,
        ingress_queue: Receiver<Packet>,
        isolate_clients: bool,
    ) -> Result<()> {
        debug!("Started tunnel inbound traffic task (tunnel queue -> interface)");

        if isolate_clients {
            relay_isolated(connection_queues, interface, ingress_queue).await
        } else {
            relay_unisolated(connection_queues, interface, ingress_queue).await
        }
    }
}

#[inline]
async fn relay_isolated(
    connection_queues: ConnectionQueues,
    interface: Arc<Interface<impl InterfaceIO>>,
    mut ingress_queue: Receiver<Packet>,
) -> Result<()> {
    loop {
        let mut packets = Vec::with_capacity(PACKET_BUFFER_SIZE);
        ingress_queue
            .recv_many(&mut packets, PACKET_BUFFER_SIZE)
            .await;

        let filtered_packets = packets
            .into_iter()
            .filter(|packet| {
                let dest_addr = match packet.destination() {
                    Ok(addr) => addr,
                    Err(e) => {
                        warn!("Received packet with malformed header structure: {e}");
                        return false;
                    }
                };
                !connection_queues.contains_key(&dest_addr)
            })
            .collect::<Vec<_>>();

        interface.write_packets(filtered_packets).await?;
    }
}

#[inline]
async fn relay_unisolated(
    connection_queues: ConnectionQueues,
    interface: Arc<Interface<impl InterfaceIO>>,
    mut ingress_queue: Receiver<Packet>,
) -> Result<()> {
    loop {
        let mut packets = Vec::with_capacity(PACKET_BUFFER_SIZE);

        ingress_queue
            .recv_many(&mut packets, PACKET_BUFFER_SIZE)
            .await;

        for packet in packets {
            let dest_addr = match packet.destination() {
                Ok(addr) => addr,
                Err(e) => {
                    warn!("Received packet with malformed header structure: {e}");
                    continue;
                }
            };

            match connection_queues.get(&dest_addr) {
                // Send the packet to the appropriate QUIC connection
                Some(connection_queue) => connection_queue.send(packet.into()).await?,
                // Send the packet to the TUN interface
                None => interface.write_packet(packet).await?,
            }
        }
    }
}
