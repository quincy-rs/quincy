#![windows_subsystem = "windows"]

use clap::Parser;
use quincy::config::{ClientConfig, FromPath};
use quincy::network::interface::tun_rs::TunRsInterface;
use quincy::utils::tracing::log_subscriber;
use quincy::{QuincyError, Result};
use quincy_client::client::QuincyClient;
use quincy_gui::ipc::{
    get_ipc_socket_path, ClientStatus, ConnectionMetrics, ConnectionStatus, IpcClient, IpcMessage,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot, Mutex};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Command line arguments for the Quincy client daemon.
#[derive(Parser)]
#[command(name = "quincy-client-daemon")]
pub struct Args {
    /// Path to the configuration file
    #[arg(long)]
    pub config_path: PathBuf,
    /// Name of the client instance
    #[arg(long)]
    pub instance_name: String,
    /// Environment variable prefix for configuration
    #[arg(long, default_value = "QUINCY_")]
    pub env_prefix: String,
}

/// The Quincy client daemon that manages VPN connections and IPC communication.
///
/// This daemon runs with elevated privileges to manage network interfaces and routes.
/// It communicates with the GUI client through IPC messages and maintains heartbeat
/// monitoring for connection health.
struct ClientDaemon {
    /// The underlying Quincy VPN client instance
    client: Arc<Mutex<Option<QuincyClient<TunRsInterface>>>>,
    /// Timestamp when the current connection was established
    connection_start_time: Arc<Mutex<Option<Instant>>>,
    /// Unique identifier for this daemon instance
    instance_name: String,
    /// Broadcast sender for shutdown notifications
    shutdown_tx: broadcast::Sender<()>,
}

impl ClientDaemon {
    /// Creates a new ClientDaemon instance.
    fn new(instance_name: String) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            client: Arc::new(Mutex::new(None)),
            connection_start_time: Arc::new(Mutex::new(None)),
            instance_name,
            shutdown_tx,
        }
    }

    /// Starts the VPN client with the given configuration.
    /// This is a blocking operation that can be cancelled via the cancel_rx channel.
    async fn start_client_cancellable(
        &self,
        config_path: PathBuf,
        env_prefix: &str,
        mut cancel_rx: oneshot::Receiver<()>,
    ) -> Result<bool> {
        let mut client_guard = self.client.lock().await;

        if client_guard.is_some() {
            return Err(QuincyError::system("Client is already running"));
        }

        let config = ClientConfig::from_path(&config_path, env_prefix)?;
        let mut client = QuincyClient::new(config);

        // Start the client in a separate task so we can listen for cancellation
        let start_future = client.start();

        tokio::select! {
            result = start_future => {
                match result {
                    Ok(()) => {
                        *self.connection_start_time.lock().await = Some(Instant::now());
                        *client_guard = Some(client);
                        info!("Client started successfully");
                        Ok(true)
                    }
                    Err(e) => Err(e)
                }
            }
            _ = &mut cancel_rx => {
                info!("Client start cancelled");
                // Client.start() was interrupted - drop the client
                drop(client);
                Ok(false)
            }
        }
    }

    /// Stops the running VPN client.
    async fn stop_client(&self) -> Result<()> {
        let mut client_guard = self.client.lock().await;

        if let Some(mut client) = client_guard.take() {
            client.stop().await?;
            client.wait_for_shutdown().await?;
            *self.connection_start_time.lock().await = None;
            info!("Client stopped successfully");
        }

        Ok(())
    }

    /// Gets the current status and metrics of the VPN client.
    async fn get_status(&self) -> ClientStatus {
        let client_guard = self.client.lock().await;

        if let Some(client) = client_guard.as_ref() {
            let status = self.determine_connection_status(client);
            let metrics = self.extract_connection_metrics(client).await;
            ClientStatus { status, metrics }
        } else {
            ClientStatus {
                status: ConnectionStatus::Disconnected,
                metrics: None,
            }
        }
    }

    /// Determines the current connection status based on client state.
    fn determine_connection_status(
        &self,
        client: &QuincyClient<TunRsInterface>,
    ) -> ConnectionStatus {
        if client.is_running() {
            if let Some(relayer) = client.relayer() {
                match relayer.connection().close_reason() {
                    None => ConnectionStatus::Connected,
                    Some(reason) => {
                        ConnectionStatus::Error(format!("Connection closed: {reason:?}"))
                    }
                }
            } else {
                ConnectionStatus::Connecting
            }
        } else {
            ConnectionStatus::Disconnected
        }
    }

    /// Extracts connection metrics from the client if available.
    async fn extract_connection_metrics(
        &self,
        client: &QuincyClient<TunRsInterface>,
    ) -> Option<ConnectionMetrics> {
        if let Some(relayer) = client.relayer() {
            let stats = relayer.connection().stats();
            let connection_duration = self
                .connection_start_time
                .lock()
                .await
                .map(|start| start.elapsed())
                .unwrap_or_default();

            Some(ConnectionMetrics {
                bytes_sent: stats.udp_tx.bytes,
                bytes_received: stats.udp_rx.bytes,
                packets_sent: stats.udp_tx.datagrams,
                packets_received: stats.udp_rx.datagrams,
                connection_duration,
                client_address: client.client_address(),
                server_address: client.server_address(),
            })
        } else {
            None
        }
    }

    /// Connects to the GUI's IPC server and handles communication.
    /// The daemon first establishes IPC, then waits for StartClient command.
    /// During VPN connection, it listens for cancellation.
    async fn run_ipc_client(&self, socket_path: &Path, config_path: &Path) -> Result<()> {
        let mut ipc_client = self.connect_to_gui_server(socket_path).await?;
        info!("Connected to GUI IPC server");

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        // Main message loop
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("IPC client received shutdown signal");
                    break;
                }
                result = ipc_client.recv() => {
                    match result {
                        Ok(message) => {
                            let should_exit = self.handle_message_with_cancel(
                                message,
                                &mut ipc_client,
                                config_path,
                            ).await?;
                            if should_exit {
                                break;
                            }
                        }
                        Err(e) => {
                            info!("IPC connection closed by GUI: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        info!("IPC client shutdown complete");
        Ok(())
    }

    /// Handles a message, with special handling for StartClient to support cancellation.
    /// Returns true if the daemon should exit.
    async fn handle_message_with_cancel(
        &self,
        message: IpcMessage,
        ipc_client: &mut IpcClient,
        config_path: &Path,
    ) -> Result<bool> {
        match message {
            IpcMessage::StartClient {
                config_path: cfg_path,
            } => {
                // Use the config path from the message, or fall back to the one from args
                let path = if cfg_path.as_os_str().is_empty() {
                    config_path.to_path_buf()
                } else {
                    cfg_path
                };

                // Create a cancellation channel
                let (cancel_tx, cancel_rx) = oneshot::channel();

                // Spawn a task to listen for cancel messages while connecting
                let cancel_tx = Arc::new(Mutex::new(Some(cancel_tx)));
                let cancel_tx_clone = cancel_tx.clone();
                let shutdown_tx = self.shutdown_tx.clone();

                // We need to handle IPC messages while the VPN is connecting
                // Run the connection with cancellation support
                let daemon = self.clone();
                let path_clone = path.clone();

                // Start connecting in a spawned task
                let mut connect_handle = tokio::spawn(async move {
                    daemon
                        .start_client_cancellable(path_clone, "QUINCY_", cancel_rx)
                        .await
                });

                // While connecting, listen for IPC messages
                loop {
                    tokio::select! {
                        // Connection completed
                        result = &mut connect_handle => {
                            match result {
                                Ok(Ok(true)) => {
                                    // Successfully connected
                                    let status = self.get_status().await;
                                    if let Err(e) = ipc_client.send(&IpcMessage::StatusUpdate(status)).await {
                                        error!("Failed to send status: {}", e);
                                    }
                                    break Ok(false);
                                }
                                Ok(Ok(false)) => {
                                    // Cancelled
                                    if let Err(e) = ipc_client.send(&IpcMessage::Error("Connection cancelled".to_string())).await {
                                        error!("Failed to send cancel response: {}", e);
                                    }
                                    break Ok(true); // Exit daemon
                                }
                                Ok(Err(e)) => {
                                    // Connection failed
                                    if let Err(send_err) = ipc_client.send(&IpcMessage::Error(e.to_string())).await {
                                        error!("Failed to send error: {}", send_err);
                                    }
                                    break Ok(false);
                                }
                                Err(e) => {
                                    error!("Connect task panicked: {}", e);
                                    break Ok(true);
                                }
                            }
                        }
                        // IPC message received while connecting
                        msg_result = ipc_client.recv() => {
                            match msg_result {
                                Ok(IpcMessage::Shutdown) | Ok(IpcMessage::StopClient) => {
                                    info!("Received cancel/shutdown while connecting");
                                    // Signal cancellation to abort the VPN connection
                                    if let Some(tx) = cancel_tx_clone.lock().await.take() {
                                        let _ = tx.send(());
                                    }
                                    let _ = shutdown_tx.send(());
                                    // Exit the daemon
                                    break Ok(true);
                                }
                                Ok(IpcMessage::GetStatus) => {
                                    // Send "connecting" status
                                    let status = ClientStatus {
                                        status: ConnectionStatus::Connecting,
                                        metrics: None,
                                    };
                                    if let Err(e) = ipc_client.send(&IpcMessage::StatusUpdate(status)).await {
                                        error!("Failed to send status: {}", e);
                                    }
                                }
                                Ok(other) => {
                                    debug!("Ignoring message while connecting: {:?}", other);
                                }
                                Err(e) => {
                                    info!("IPC connection lost while connecting: {}", e);
                                    // Signal cancellation
                                    if let Some(tx) = cancel_tx_clone.lock().await.take() {
                                        let _ = tx.send(());
                                    }
                                    break Ok(true);
                                }
                            }
                        }
                    }
                }
            }
            IpcMessage::StopClient => {
                let response = self.handle_stop_client_message().await;
                ipc_client.send(&response).await?;
                Ok(false)
            }
            IpcMessage::GetStatus => {
                let status = self.get_status().await;
                ipc_client.send(&IpcMessage::StatusUpdate(status)).await?;
                Ok(false)
            }
            IpcMessage::Shutdown => {
                let response = self.handle_shutdown_message().await;
                ipc_client.send(&response).await?;
                Ok(true)
            }
            _ => {
                ipc_client
                    .send(&IpcMessage::Error("Invalid message".to_string()))
                    .await?;
                Ok(false)
            }
        }
    }

    /// Connects to the GUI's IPC server with retry logic.
    async fn connect_to_gui_server(&self, socket_path: &Path) -> Result<IpcClient> {
        const MAX_RETRIES: u32 = 30;
        const RETRY_DELAY: Duration = Duration::from_millis(500);

        for attempt in 1..=MAX_RETRIES {
            match IpcClient::connect(socket_path).await {
                Ok(client) => {
                    info!(
                        "Successfully connected to GUI server on attempt {}",
                        attempt
                    );
                    return Ok(client);
                }
                Err(e) => {
                    if attempt == MAX_RETRIES {
                        error!(
                            "Failed to connect to GUI server after {} attempts: {}",
                            MAX_RETRIES, e
                        );
                        return Err(e);
                    }
                    debug!(
                        "Connection attempt {} failed, retrying in {:?}: {}",
                        attempt, RETRY_DELAY, e
                    );
                    sleep(RETRY_DELAY).await;
                }
            }
        }

        unreachable!()
    }

    /// Handles a StopClient IPC message.
    async fn handle_stop_client_message(&self) -> IpcMessage {
        match self.stop_client().await {
            Ok(()) => {
                let status = self.get_status().await;
                IpcMessage::StatusUpdate(status)
            }
            Err(e) => IpcMessage::Error(e.to_string()),
        }
    }

    /// Handles a Shutdown IPC message.
    async fn handle_shutdown_message(&self) -> IpcMessage {
        info!("Received shutdown request, stopping client and daemon");
        if let Err(e) = self.stop_client().await {
            error!("Failed to stop client during shutdown: {}", e);
        }

        if let Err(e) = self.shutdown_tx.send(()) {
            warn!("Failed to send shutdown signal: {}", e);
        }

        IpcMessage::Shutdown
    }
}

impl Clone for ClientDaemon {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            connection_start_time: self.connection_start_time.clone(),
            instance_name: self.instance_name.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }
}

/// Main entry point for the Quincy client daemon.
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    initialize_logging();

    // Validate instance name defensively to prevent unsafe IPC names
    use quincy_gui::validation;
    validation::validate_instance_name(&args.instance_name)?;

    info!("Starting Quincy client daemon: {}", args.instance_name);

    let daemon = ClientDaemon::new(args.instance_name.clone());
    let socket_path = get_ipc_socket_path(&args.instance_name);

    daemon
        .run_ipc_client(&socket_path, &args.config_path)
        .await?;

    info!("Daemon shutdown complete");
    Ok(())
}

/// Initializes the logging system for the daemon.
fn initialize_logging() {
    let _logger = tracing::subscriber::set_global_default(log_subscriber("info"));
}
