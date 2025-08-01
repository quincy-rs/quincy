use anyhow::{anyhow, Result};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use quincy::network::interface::{Interface, InterfaceIO};
use quincy::utils::tasks::abort_all;
use quinn::{Connection, VarInt};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{debug, info};

pub struct ClientRelayer<I: InterfaceIO> {
    #[allow(unused)]
    interface: Arc<Interface<I>>,
    connection: Connection,
    relayer_task: JoinHandle<Result<()>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl<I: InterfaceIO> ClientRelayer<I> {
    /// Creates a new instance of the client relayer and starts relaying packets between
    /// the TUN interface and the QUIC connection.
    pub fn start(interface: Interface<I>, connection: Connection) -> Result<Self> {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let interface = Arc::new(interface);

        let relayer_task = tokio::spawn(Self::relay_packets(
            interface.clone(),
            connection.clone(),
            shutdown_rx,
        ));

        Ok(Self {
            interface,
            connection,
            relayer_task,
            shutdown_tx,
        })
    }

    /// Send a shutdown signal to the relayer task.
    pub async fn stop(&mut self) -> Result<()> {
        // Send shutdown signal to the relayer task
        self.shutdown_tx
            .send(())
            .map_err(|_| anyhow!("Failed to send shutdown signal"))?;

        Ok(())
    }

    /// Waits for the relayer task to finish. Consumes this Relayer instance.
    pub async fn wait_for_shutdown(self) -> Result<()> {
        // Wait for the relayer task to finish
        self.relayer_task
            .await
            .map_err(|_| anyhow!("Relayer task failed"))?
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Relays packets between the TUN interface and the Quincy clients.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `interface` - the TUN interface
    async fn relay_packets(
        interface: Arc<Interface<I>>,
        connection: Connection,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(Self::process_inbound_traffic(
                connection.clone(),
                interface.clone(),
            )),
            tokio::spawn(Self::process_outgoing_traffic(
                connection.clone(),
                interface.clone(),
            )),
        ]);

        interface.configure()?;

        let result = tokio::select! {
            Some(task_result) = tasks.next() => task_result?,
            _ = shutdown_rx.recv() => {
                info!("Received shutdown signal, shutting down");
                Ok(())
            },
            _ = signal::ctrl_c() => {
                info!("Received shutdown signal, shutting down");
                Ok(())
            },
        };

        // Stop all running tasks
        let _ = abort_all(tasks).await;

        // Close the QUIC connection
        connection.close(VarInt::from_u32(0x01), "Client shutdown".as_bytes());

        result
    }

    /// Handles incoming packets from the TUN interface and relays them to the Quincy server.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `interface` - TUN interface
    async fn process_outgoing_traffic(
        connection: Connection,
        interface: Arc<Interface<I>>,
    ) -> Result<()> {
        debug!("Started outgoing traffic task (interface -> QUIC tunnel)");

        loop {
            let packets = interface.read_packets().await?;

            for packet in packets {
                connection
                    .send_datagram(packet.into())
                    .map_err(|e| anyhow!("Failed to send packet: {e}"))?;
            }
        }
    }

    /// Handles incoming packets from the Quincy server and relays them to the TUN interface queue.
    ///
    /// ### Arguments
    /// - `connection` - a Quinn connection representing the connection to the Quincy server
    /// - `interface` - TUN interface
    async fn process_inbound_traffic(
        connection: Connection,
        interface: Arc<Interface<I>>,
    ) -> Result<()> {
        debug!("Started inbound traffic task (QUIC tunnel -> interface)");

        loop {
            let packet = connection.read_datagram().await?.into();

            interface.write_packet(packet).await?;
        }
    }
}
