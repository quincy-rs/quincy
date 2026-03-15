pub mod address_pool;
mod connection;
pub mod session;

#[cfg(feature = "metrics")]
mod metrics;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
#[cfg(feature = "metrics")]
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use dashmap::DashMap;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use quinn::{Endpoint, VarInt};
use tokio::signal;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, info, warn};

use crate::server::address_pool::AddressPoolManager;
use crate::server::connection::{Assigned, QuincyConnection};
use crate::server::session::{ConnectionSession, UserSessionRegistry};
use crate::users::UsersFile;
use quincy::config::{
    AddressRange, AllowedNoiseKeys, NoiseKeyExchange, ServerConfig, ServerProtocolConfig,
};
use quincy::constants::{PACKET_BUFFER_SIZE, PACKET_CHANNEL_SIZE, QUINN_RUNTIME};
use quincy::network::interface::{Interface, InterfaceIO};
use quincy::network::packet::Packet;
use quincy::network::socket::bind_socket;
use quincy::utils::tasks::abort_all;
use quincy::Result;

/// Map of connection addresses to their TX channel.
type ConnectionQueues = Arc<DashMap<IpAddr, Sender<Bytes>>>;

/// Result of an IP assignment task, carrying the context needed for cleanup on failure.
struct AssignmentResult {
    result: Result<QuincyConnection<Assigned>>,
    quic_connection: quinn::Connection,
}

/// Represents a Quincy server encapsulating Quincy connections and TUN interface IO.
pub struct QuincyServer {
    config: ServerConfig,
    connection_queues: ConnectionQueues,
    address_pool: Arc<AddressPoolManager>,
    users: Arc<UsersFile>,
    session_registry: Arc<UserSessionRegistry>,
}

impl QuincyServer {
    /// Creates a new instance of the Quincy tunnel.
    ///
    /// Loads the users file and initializes the address pool from the tunnel network.
    ///
    /// ### Arguments
    /// - `config` - the server configuration
    pub fn new(config: ServerConfig) -> Result<Self> {
        let users = UsersFile::load(&config.users_file)?;

        let user_pools: HashMap<String, Vec<AddressRange>> = users
            .users
            .iter()
            .filter(|(_, entry)| !entry.address_pool.is_empty())
            .map(|(name, entry)| (name.clone(), entry.address_pool.clone()))
            .collect();

        let address_pool = AddressPoolManager::new(config.tunnel_network, user_pools)?;

        Ok(Self {
            config,
            connection_queues: Arc::new(DashMap::new()),
            address_pool: Arc::new(address_pool),
            users: Arc::new(users),
            session_registry: Arc::new(UserSessionRegistry::new()),
        })
    }

    /// Starts the tasks for this instance of Quincy tunnel and listens for incoming connections.
    pub async fn run<I: InterfaceIO>(&self) -> Result<()> {
        let interface: Interface<I> = Interface::create(
            self.config.tunnel_network,
            self.config.connection.mtu,
            Some(self.config.tunnel_network.network()),
            self.config.interface_name.clone(),
            None,
            None,
        )?;
        let interface = Arc::new(interface);

        #[cfg(feature = "metrics")]
        if self.config.metrics.enabled {
            use crate::server::metrics::init_metrics;

            init_metrics(&self.config.metrics)?;
        }

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

        let handler_task = self.handle_connections(sender);

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
    /// - `ingress_queue` - the queue for sending data to the TUN interface
    async fn handle_connections(&self, ingress_queue: Sender<Packet>) -> Result<()> {
        let endpoint = self.create_quinn_endpoint()?;

        info!(
            "Starting connection handler: {}",
            endpoint.local_addr().expect("Endpoint has a local address")
        );

        let protocol = Arc::new(self.config.protocol.clone());
        let server_address = self.config.tunnel_network;
        let users = self.users.clone();
        let address_pool = self.address_pool.clone();
        let session_registry = self.session_registry.clone();

        let mut assignment_tasks = FuturesUnordered::new();
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

                    let quic_connection_clone = quic_connection.clone();
                    let connection = QuincyConnection::new(
                        quic_connection,
                        ingress_queue.clone(),
                    );

                    // Identify synchronously (reads peer_identity + HashMap lookup)
                    let connection = match connection.identify(&protocol, &users) {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("Failed to identify client: {e}");
                            quic_connection_clone.close(VarInt::from_u32(0x02), "Session establishment failed".as_bytes());
                            continue;
                        }
                    };

                    let address_pool = address_pool.clone();
                    let server_addr = server_address;

                    assignment_tasks.push(async move {
                        let result = connection.assign_ip(&address_pool, server_addr).await;
                        AssignmentResult {
                            result,
                            quic_connection: quic_connection_clone,
                        }
                    });
                }

                // Assignment tasks
                Some(assignment) = assignment_tasks.next() => {
                    let connection = match assignment.result {
                        Ok(connection) => connection,
                        Err(e) => {
                            warn!("Failed to assign IP to client: {e}");
                            assignment.quic_connection.close(
                                VarInt::from_u32(0x02),
                                "Session establishment failed".as_bytes(),
                            );
                            continue;
                        }
                    };

                    let client_address = connection.client_address();
                    let username = connection.username().to_string();

                    // Resolve effective bandwidth limit:
                    // per-user override > server default > None (unlimited)
                    let bandwidth_limit = self
                        .users
                        .users
                        .get(&username)
                        .and_then(|entry| entry.bandwidth_limit)
                        .or(self.config.default_bandwidth_limit);

                    // Register session and obtain the shared rate limiter
                    let rate_limiter = session_registry.add_connection(
                        &username,
                        ConnectionSession {
                            client_address,
                            connected_at: Instant::now(),
                        },
                        bandwidth_limit,
                    );

                    let (connection_sender, connection_receiver) = channel(PACKET_CHANNEL_SIZE);

                    connection_tasks.push(tokio::spawn(connection.run(
                        connection_receiver,
                        rate_limiter,
                        #[cfg(feature = "metrics")]
                        Duration::from_secs(self.config.metrics.reporting_interval_s),
                    )));
                    self.connection_queues
                        .insert(client_address.addr(), connection_sender);
                }

                // Connection tasks
                Some(connection) = connection_tasks.next() => {
                    let (connection, err) = connection?;
                    let username = connection.username();
                    let client_address = connection.client_address();

                    self.connection_queues.remove(&client_address.addr());
                    self.address_pool.release_address(username, &client_address.addr());
                    session_registry.remove_connection(username, &client_address);

                    warn!(
                        "Connection with client {} (user '{username}') has encountered an error: {err}",
                        client_address.addr()
                    );
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
        // Build allowed keys/fingerprints from the users file
        let (allowed_keys, allowed_fingerprints) = match &self.config.protocol {
            ServerProtocolConfig::Noise(noise) => {
                let keys = match noise.key_exchange {
                    NoiseKeyExchange::Standard => Some(AllowedNoiseKeys::Standard(
                        self.users.collect_noise_public_keys(),
                    )),
                    NoiseKeyExchange::Hybrid => Some(AllowedNoiseKeys::Hybrid(
                        self.users.collect_noise_pq_public_keys(),
                    )),
                };
                (keys, None)
            }
            ServerProtocolConfig::Tls(_) => (None, Some(self.users.collect_cert_fingerprints())),
        };

        let quinn_config = self
            .config
            .as_quinn_server_config(allowed_keys, allowed_fingerprints)?;

        let socket = bind_socket(
            SocketAddr::new(self.config.bind_address, self.config.bind_port),
            self.config.connection.send_buffer_size as usize,
            self.config.connection.recv_buffer_size as usize,
            self.config.reuse_socket,
        )?;

        let endpoint_config = self
            .config
            .connection
            .as_endpoint_config(self.config.noise_key_exchange())?;
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

            match connection_queue.try_send(packet.into()) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    debug!("Dropping outbound packet for {dest_addr}: per-client queue full");
                }
                Err(TrySendError::Closed(_)) => {
                    debug!("Dropping outbound packet for {dest_addr}: connection closed");
                }
            }
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
        let count = ingress_queue
            .recv_many(&mut packets, PACKET_BUFFER_SIZE)
            .await;

        // ingress_queue closed
        if count == 0 {
            return Ok(());
        }

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

        let count = ingress_queue
            .recv_many(&mut packets, PACKET_BUFFER_SIZE)
            .await;

        // ingress_queue closed
        if count == 0 {
            return Ok(());
        }

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
                Some(connection_queue) => match connection_queue.try_send(packet.into()) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        debug!("Dropping client-to-client packet for {dest_addr}: queue full");
                    }
                    Err(TrySendError::Closed(_)) => {
                        debug!(
                            "Dropping client-to-client packet for {dest_addr}: connection closed"
                        );
                    }
                },
                // Send the packet to the TUN interface
                None => interface.write_packet(packet).await?,
            }
        }
    }
}
