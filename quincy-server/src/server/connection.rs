use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use governor::Jitter;
use ipnet::IpNet;
use quinn::Connection;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, info};

use crate::identity;
use crate::server::address_pool::AddressPool;
use crate::server::session::BandwidthLimiter;
use crate::users::UsersFile;
use quincy::config::ServerProtocolConfig;
use quincy::ip_assignment::{self, IpAssignment};
use quincy::network::packet::Packet;
use quincy::utils::tasks::abort_all;
use quincy::{QuincyError, Result};

/// Default timeout for IP assignment exchange.
const IP_ASSIGNMENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Initial state: connection established but client not yet identified.
pub struct New;

/// Client identified via handshake peer identity.
pub struct Identified {
    pub username: String,
}

/// Client identified and tunnel IP assigned.
pub struct Assigned {
    pub username: String,
    pub client_address: IpNet,
}

/// Represents a Quincy connection whose lifecycle phase is tracked at the type level.
///
/// The state parameter `S` encodes which operations have been completed:
/// - [`New`] — QUIC handshake done, client not yet identified
/// - [`Identified`] — peer identity resolved to a username
/// - [`Assigned`] — tunnel IP allocated and sent to the client
pub struct QuincyConnection<S> {
    connection: Connection,
    ingress_queue: Sender<Packet>,
    state: S,
}

impl QuincyConnection<New> {
    /// Creates a new connection in the initial (unidentified) state.
    ///
    /// ### Arguments
    /// - `connection` - the underlying QUIC connection
    /// - `tun_queue` - the queue to send data to the TUN interface
    pub fn new(connection: Connection, tun_queue: Sender<Packet>) -> Self {
        Self {
            connection,
            ingress_queue: tun_queue,
            state: New,
        }
    }

    /// Identifies the client from the handshake.
    ///
    /// Uses the peer identity from the completed QUIC handshake (Noise public key
    /// or TLS client certificate) to look up the username.
    ///
    /// ### Arguments
    /// - `protocol` - the server protocol configuration
    /// - `users` - the parsed users file
    pub fn identify(
        self,
        protocol: &ServerProtocolConfig,
        users: &UsersFile,
    ) -> Result<QuincyConnection<Identified>> {
        let username = identity::identify_peer(&self.connection, protocol, users)?;

        Ok(QuincyConnection {
            connection: self.connection,
            ingress_queue: self.ingress_queue,
            state: Identified { username },
        })
    }
}

impl QuincyConnection<Identified> {
    /// Returns the username resolved during identification.
    #[allow(dead_code)]
    pub fn username(&self) -> &str {
        &self.state.username
    }

    /// Assigns an IP address and sends the assignment to the client.
    ///
    /// Allocates an IP from the address pool and sends the assignment
    /// to the client over a uni-stream. On send failure, the address
    /// is released back to the pool.
    ///
    /// ### Arguments
    /// - `address_pool` - the pool of available client IP addresses
    /// - `server_address` - the server's tunnel address
    pub async fn assign_ip(
        self,
        address_pool: &AddressPool,
        server_address: IpNet,
    ) -> Result<QuincyConnection<Assigned>> {
        let client_address = address_pool
            .next_available_address()
            .ok_or(quincy::error::AuthError::AddressPoolExhausted)?;

        let assignment = IpAssignment {
            client_address,
            server_address,
        };

        if let Err(e) =
            ip_assignment::send_ip_assignment(&self.connection, &assignment, IP_ASSIGNMENT_TIMEOUT)
                .await
        {
            address_pool.release_address(&client_address.addr());
            return Err(e);
        }

        info!(
            "Connection established: user = {}, client address = {}, remote address = {}",
            self.state.username,
            client_address.addr(),
            self.connection.remote_address().ip(),
        );

        Ok(QuincyConnection {
            connection: self.connection,
            ingress_queue: self.ingress_queue,
            state: Assigned {
                username: self.state.username,
                client_address,
            },
        })
    }
}

impl QuincyConnection<Assigned> {
    /// Returns the username resolved during identification.
    pub fn username(&self) -> &str {
        &self.state.username
    }

    /// Returns the client's assigned tunnel address.
    pub fn client_address(&self) -> IpNet {
        self.state.client_address
    }

    /// Starts the IO and metrics tasks for this connection.
    ///
    /// ### Arguments
    /// - `egress_queue` - channel carrying packets destined for this client
    /// - `rate_limiter` - optional shared bandwidth limiter for the user
    /// - `metrics_interval` - how often to report per-connection metrics
    pub async fn run(
        self,
        egress_queue: Receiver<Bytes>,
        rate_limiter: Option<Arc<BandwidthLimiter>>,
        #[cfg(feature = "metrics")] metrics_interval: Duration,
    ) -> (Self, QuincyError) {
        let client_address = self.state.client_address.addr();

        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(Self::process_outgoing_data(
                self.connection.clone(),
                egress_queue,
                rate_limiter.clone(),
            )),
            tokio::spawn(Self::process_incoming_data(
                self.connection.clone(),
                self.ingress_queue.clone(),
                client_address,
                rate_limiter,
            )),
        ]);

        #[cfg(feature = "metrics")]
        tasks.push(tokio::spawn(Self::report_metrics(
            self.connection.clone(),
            metrics_interval,
            self.state.username.clone(),
            self.state.client_address.addr(),
        )));

        let res = tasks
            .next()
            .await
            .expect("tasks is not empty")
            .expect("task is joinable");

        let _ = abort_all(tasks).await;

        match res {
            Err(e) => (self, e),
            Ok(()) => (
                self,
                QuincyError::system("Connection task exited unexpectedly"),
            ),
        }
    }

    /// Processes outgoing data and sends it to the QUIC connection.
    ///
    /// ### Arguments
    /// - `connection` - the QUIC connection to send datagrams on
    /// - `egress_queue` - the queue to receive data from the TUN interface
    /// - `rate_limiter` - optional shared bandwidth limiter for the user
    async fn process_outgoing_data(
        connection: Connection,
        mut egress_queue: Receiver<Bytes>,
        rate_limiter: Option<Arc<BandwidthLimiter>>,
    ) -> Result<()> {
        loop {
            let data = egress_queue
                .recv()
                .await
                .ok_or(QuincyError::system("Egress queue has been closed"))?;

            if let Some(ref limiter) = rate_limiter {
                let tokens = (data.len() as u32 / 1024)
                    .max(1)
                    .try_into()
                    .expect("token amount is always non-zero");

                let _ = limiter
                    .until_n_ready_with_jitter(tokens, Jitter::up_to(Duration::from_millis(5)))
                    .await;
            }

            connection.send_datagram(data)?;
        }
    }

    /// Processes incoming data and sends it to the TUN interface queue.
    ///
    /// Validates that the source IP of each incoming datagram matches the client's
    /// assigned tunnel address, dropping packets with mismatched or unparseable
    /// source IPs to prevent IP spoofing between authenticated clients.
    ///
    /// ### Arguments
    /// - `connection` - the QUIC connection to read datagrams from
    /// - `ingress_queue` - the queue to send validated packets to the TUN interface
    /// - `client_address` - the client's assigned tunnel IP address
    /// - `rate_limiter` - optional shared bandwidth limiter for the user
    async fn process_incoming_data(
        connection: Connection,
        ingress_queue: Sender<Packet>,
        client_address: IpAddr,
        rate_limiter: Option<Arc<BandwidthLimiter>>,
    ) -> Result<()> {
        loop {
            let packet: Packet = connection.read_datagram().await?.into();
            let source_address = match packet.source() {
                Ok(source) => source,
                Err(err) => {
                    debug!("Dropping packet: unable to parse source IP from header due to {err}");
                    continue;
                }
            };

            if source_address != client_address {
                debug!(
                    "Dropping packet: source IP {source_address} does not match assigned address {client_address}"
                );
                continue;
            }

            if let Some(ref limiter) = rate_limiter {
                let tokens = (packet.len() as u32 / 1024)
                    .max(1)
                    .try_into()
                    .expect("token amount is always non-zero");

                let _ = limiter
                    .until_n_ready_with_jitter(tokens, Jitter::up_to(Duration::from_millis(5)))
                    .await;
            }

            ingress_queue.send(packet).await?;
        }
    }

    /// Periodically polls `quinn::Connection::stats()` and updates Prometheus
    /// metrics counters.
    ///
    /// Runs until the connection handle is closed. This task will be aborted by
    /// the parent `run()` when the other tasks exit.
    ///
    /// ### Arguments
    /// - `connection` - the QUIC connection handle (cheap Arc clone)
    /// - `reporting_interval` - how often to poll and report metrics
    /// - `username` - the username associated with this connection
    /// - `client_ip` - the client IP address associated with this connection
    #[cfg(feature = "metrics")]
    async fn report_metrics(
        connection: Connection,
        reporting_interval: Duration,
        username: String,
        client_ip: IpAddr,
    ) -> Result<()> {
        use metrics::{counter, gauge};

        let connected_at = std::time::Instant::now();
        let mut interval = tokio::time::interval(reporting_interval);

        let labels = [("user", username), ("connection", client_ip.to_string())];

        loop {
            interval.tick().await;

            let stats = connection.stats();

            counter!("quincy_bytes_tx_total", &labels).absolute(stats.udp_tx.bytes);
            counter!("quincy_bytes_rx_total", &labels).absolute(stats.udp_rx.bytes);
            counter!("quincy_datagrams_tx_total", &labels).absolute(stats.udp_tx.datagrams);
            counter!("quincy_datagrams_rx_total", &labels).absolute(stats.udp_rx.datagrams);

            gauge!("quincy_connection_rtt_seconds", &labels).set(stats.path.rtt.as_secs_f64());
            gauge!("quincy_connection_duration_seconds", &labels)
                .set(connected_at.elapsed().as_secs_f64());
        }
    }
}
