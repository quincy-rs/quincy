use crate::{auth::server::AuthServer, utils::tasks::abort_all};
use anyhow::{anyhow, Error, Result};
use bytes::Bytes;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use ipnet::IpNet;

use crate::network::packet::Packet;
use quinn::Connection;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::info;

/// Represents a Quincy connection encapsulating authentication and IO.
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

    /// Attempts to authenticate the client.
    pub async fn authenticate(mut self, auth_server: &AuthServer) -> Result<Self> {
        let (username, client_address) =
            auth_server.handle_authentication(&self.connection).await?;

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
    pub async fn run(self, egress_queue: Receiver<Bytes>) -> (Self, Error) {
        if self.username.is_none() {
            let client_address = self.connection.remote_address();
            return (
                self,
                anyhow!("Client '{}' is not authenticated", client_address.ip()),
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
                .ok_or(anyhow!("Egress queue has been closed"))?;

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
            .ok_or(anyhow!("Connection is unauthenticated"))
    }

    /// Returns the client address associated with this connection.
    pub fn client_address(&self) -> Result<&IpNet> {
        self.client_address
            .as_ref()
            .ok_or(anyhow!("Connection is unauthenticated"))
    }
}
