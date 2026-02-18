use std::time::Duration;

use bytes::Bytes;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use ipnet::IpNet;
use quinn::Connection;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::info;

use crate::users::UsersFile;
use quincy::config::ServerProtocolConfig;
use quincy::ip_assignment::{self, IpAssignment};
use quincy::network::packet::Packet;
use quincy::utils::tasks::abort_all;
use quincy::{QuincyError, Result};

use crate::identity;
use crate::server::address_pool::AddressPool;

/// Default timeout for IP assignment exchange.
const IP_ASSIGNMENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Represents a Quincy connection encapsulating identification and IO.
#[derive(Clone)]
pub struct QuincyConnection {
    connection: Connection,
    username: Option<String>,
    client_address: Option<IpNet>,
    ingress_queue: Sender<Packet>,
}

impl QuincyConnection {
    /// Creates a new instance of the Quincy connection.
    ///
    /// ### Arguments
    /// - `connection` - the underlying QUIC connection
    /// - `tun_queue` - the queue to send data to the TUN interface
    pub fn new(connection: Connection, tun_queue: Sender<Packet>) -> Self {
        Self {
            connection,
            username: None,
            client_address: None,
            ingress_queue: tun_queue,
        }
    }

    /// Identifies the client from the handshake and assigns an IP address.
    ///
    /// Uses the peer identity from the completed QUIC handshake (Noise public key
    /// or TLS client certificate) to look up the username, allocates an IP from the
    /// address pool, and sends the assignment to the client over a uni-stream.
    ///
    /// ### Arguments
    /// - `protocol` - the server protocol configuration
    /// - `users` - the parsed users file
    /// - `address_pool` - the pool of available client IP addresses
    /// - `server_address` - the server's tunnel address
    pub async fn identify_and_assign(
        mut self,
        protocol: &ServerProtocolConfig,
        users: &UsersFile,
        address_pool: &AddressPool,
        server_address: IpNet,
    ) -> Result<Self> {
        let (username, client_address) =
            identity::identify_and_assign(&self.connection, protocol, users, address_pool).await?;

        let assignment = IpAssignment {
            client_address,
            server_address,
        };

        ip_assignment::send_ip_assignment(&self.connection, &assignment, IP_ASSIGNMENT_TIMEOUT)
            .await?;

        info!(
            "Connection established: user = {}, client address = {}, remote address = {}",
            username,
            client_address.addr(),
            self.connection.remote_address().ip(),
        );

        self.username = Some(username);
        self.client_address = Some(client_address);

        Ok(self)
    }

    /// Starts the tasks for this instance of Quincy connection.
    pub async fn run(self, egress_queue: Receiver<Bytes>) -> (Self, QuincyError) {
        if self.username.is_none() {
            let client_address = self.connection.remote_address();
            return (
                self,
                QuincyError::system(format!(
                    "Client '{}' is not authenticated",
                    client_address.ip()
                )),
            );
        }

        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(Self::process_outgoing_data(
                self.connection.clone(),
                egress_queue,
            )),
            tokio::spawn(Self::process_incoming_data(
                self.connection.clone(),
                self.ingress_queue.clone(),
            )),
        ]);

        let res = tasks
            .next()
            .await
            .expect("tasks is not empty")
            .expect("task is joinable");

        let _ = abort_all(tasks).await;

        (self, res.expect_err("task failed"))
    }

    /// Processes outgoing data and sends it to the QUIC connection.
    ///
    /// ### Arguments
    /// - `egress_queue` - the queue to receive data from the TUN interface
    async fn process_outgoing_data(
        connection: Connection,
        mut egress_queue: Receiver<Bytes>,
    ) -> Result<()> {
        loop {
            let data = egress_queue
                .recv()
                .await
                .ok_or(QuincyError::system("Egress queue has been closed"))?;

            connection.send_datagram(data)?;
        }
    }

    /// Processes incoming data and sends it to the TUN interface queue.
    async fn process_incoming_data(
        connection: Connection,
        ingress_queue: Sender<Packet>,
    ) -> Result<()> {
        loop {
            let packet = connection.read_datagram().await?.into();

            ingress_queue.send(packet).await?;
        }
    }

    /// Returns the username associated with this connection.
    #[allow(dead_code)]
    pub fn username(&self) -> Result<&str> {
        self.username
            .as_deref()
            .ok_or(QuincyError::system("Connection is unauthenticated"))
    }

    /// Returns the client address associated with this connection.
    pub fn client_address(&self) -> Result<&IpNet> {
        self.client_address
            .as_ref()
            .ok_or(QuincyError::system("Connection is unauthenticated"))
    }
}
