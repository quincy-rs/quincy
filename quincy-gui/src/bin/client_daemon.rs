use anyhow::Result;
use clap::Parser;
use quincy::config::{ClientConfig, FromPath};
use quincy::network::interface::tun_rs::TunRsInterface;
use quincy::utils::tracing::log_subscriber;
use quincy_client::client::QuincyClient;
use quincy_gui::ipc::{
    get_ipc_socket_path, ClientStatus, ConnectionMetrics, ConnectionStatus, IpcConnection,
    IpcMessage, IpcServer,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Mutex};
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
    /// Timestamp of the last received heartbeat from the GUI
    last_heartbeat: Arc<Mutex<Option<Instant>>>,
}

impl ClientDaemon {
    /// Creates a new ClientDaemon instance.
    ///
    /// # Arguments
    /// * `instance_name` - Unique identifier for this daemon instance
    ///
    /// # Returns
    /// A new ClientDaemon with all fields initialized to their default states
    fn new(instance_name: String) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            client: Arc::new(Mutex::new(None)),
            connection_start_time: Arc::new(Mutex::new(None)),
            instance_name,
            shutdown_tx,
            last_heartbeat: Arc::new(Mutex::new(None)),
        }
    }

    /// Starts the VPN client with the given configuration.
    ///
    /// # Arguments
    /// * `config_path` - Path to the client configuration file
    /// * `env_prefix` - Prefix for environment variable overrides
    ///
    /// # Returns
    /// * `Ok(())` if the client started successfully
    /// * `Err` if the client is already running or failed to start
    ///
    /// # Errors
    /// Returns an error if:
    /// - A client is already running
    /// - The configuration file cannot be loaded
    /// - The client fails to start
    async fn start_client(&self, config_path: PathBuf, env_prefix: &str) -> Result<()> {
        let mut client_guard = self.client.lock().await;

        if client_guard.is_some() {
            return Err(anyhow::anyhow!("Client is already running"));
        }

        let config = ClientConfig::from_path(&config_path, env_prefix)?;
        let mut client = QuincyClient::new(config);

        client.start().await?;

        *self.connection_start_time.lock().await = Some(Instant::now());
        *client_guard = Some(client);

        info!("Client started successfully");
        Ok(())
    }

    /// Stops the running VPN client.
    ///
    /// # Returns
    /// * `Ok(())` if the client was stopped successfully or wasn't running
    /// * `Err` if the client failed to stop gracefully
    ///
    /// # Errors
    /// Returns an error if the client shutdown process fails
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
    ///
    /// # Returns
    /// A `ClientStatus` containing the connection state and performance metrics
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
    ///
    /// # Arguments
    /// * `client` - Reference to the VPN client
    ///
    /// # Returns
    /// The current connection status
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
    ///
    /// # Arguments
    /// * `client` - Reference to the VPN client
    ///
    /// # Returns
    /// Connection metrics if available, None otherwise
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
            })
        } else {
            None
        }
    }

    /// Runs the IPC server to handle communication with GUI clients.
    ///
    /// This method starts the IPC server and spawns a heartbeat monitoring task.
    /// It handles incoming connections and processes IPC messages until a shutdown signal is received.
    ///
    /// # Arguments
    /// * `socket_path` - Path to the Unix domain socket for IPC communication
    ///
    /// # Returns
    /// * `Ok(())` when the server shuts down gracefully
    /// * `Err` if the server fails to start
    ///
    /// # Errors
    /// Returns an error if the IPC server cannot be created or bound to the socket path
    async fn run_ipc_server(&self, socket_path: &std::path::Path) -> Result<()> {
        let server = IpcServer::new(socket_path)?;
        info!("IPC server started");

        let mut shutdown_rx = self.shutdown_tx.subscribe();
        self.start_heartbeat_monitor();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("IPC server received shutdown signal, stopping server");
                    break;
                }
                result = server.accept() => {
                    self.handle_connection_result(result);
                }
            }
        }

        info!("IPC server shutdown complete");
        Ok(())
    }

    /// Handles the result of accepting a new IPC connection.
    ///
    /// # Arguments
    /// * `result` - Result of the connection accept operation
    fn handle_connection_result(&self, result: Result<IpcConnection>) {
        match result {
            Ok(connection) => {
                info!("IPC client connected");
                self.handle_client_connection(connection);
            }
            Err(e) => {
                error!("Failed to accept IPC connection: {}", e);
            }
        }
    }

    /// Starts the heartbeat monitoring task.
    ///
    /// This spawns a background task that monitors heartbeat messages from the GUI
    /// and initiates shutdown if heartbeats are not received within the timeout period.
    fn start_heartbeat_monitor(&self) {
        let heartbeat_daemon = self.clone();
        tokio::spawn(async move {
            heartbeat_daemon.monitor_heartbeat().await;
        });
    }

    /// Handles a new client connection by spawning a task to process messages.
    ///
    /// # Arguments
    /// * `connection` - The IPC connection to handle
    fn handle_client_connection(&self, mut connection: IpcConnection) {
        let daemon = self.clone();
        tokio::spawn(async move {
            daemon.process_client_messages(&mut connection).await;
        });
    }

    /// Processes messages from a client connection.
    ///
    /// # Arguments
    /// * `connection` - The IPC connection to read messages from
    async fn process_client_messages(&self, connection: &mut IpcConnection) {
        loop {
            match connection.recv().await {
                Ok(message) => {
                    let response = self.handle_message(message).await;
                    if let Err(e) = connection.send(&response).await {
                        error!("Failed to send IPC response: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    warn!("IPC connection error: {}", e);
                    break;
                }
            }
        }
    }

    /// Monitors heartbeat messages from the GUI client.
    ///
    /// This task runs continuously and checks for heartbeat messages. If no heartbeat
    /// is received within 15 seconds, it initiates a daemon shutdown.
    ///
    /// The heartbeat mechanism ensures that the daemon doesn't remain running if
    /// the GUI client has crashed or been forcefully terminated.
    async fn monitor_heartbeat(&self) {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
        const CHECK_INTERVAL: Duration = Duration::from_secs(1);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    debug!("Heartbeat monitor shutting down");
                    break;
                }
                _ = tokio::time::sleep(CHECK_INTERVAL) => {
                    if self.should_shutdown_due_to_heartbeat_timeout(HEARTBEAT_TIMEOUT).await {
                        self.initiate_heartbeat_timeout_shutdown().await;
                        return;
                    }
                }
            }
        }
    }

    /// Checks if the daemon should shutdown due to heartbeat timeout.
    ///
    /// # Arguments
    /// * `timeout` - Maximum allowed time since last heartbeat
    ///
    /// # Returns
    /// `true` if shutdown should be initiated, `false` otherwise
    async fn should_shutdown_due_to_heartbeat_timeout(&self, timeout: Duration) -> bool {
        let last_heartbeat_opt = *self.last_heartbeat.lock().await;

        let Some(last_heartbeat) = last_heartbeat_opt else {
            debug!("No heartbeat received yet, monitoring will start after first heartbeat");
            return false;
        };

        let time_since_heartbeat = last_heartbeat.elapsed();

        if time_since_heartbeat > timeout {
            warn!(
                "No heartbeat received for {:?}, shutting down daemon",
                time_since_heartbeat
            );
            return true;
        }

        debug!(
            "Heartbeat check: last heartbeat {:?} ago",
            time_since_heartbeat
        );
        false
    }

    /// Initiates shutdown procedure due to heartbeat timeout.
    ///
    /// This method stops the client, sends shutdown signals, and exits the process
    /// if graceful shutdown fails.
    async fn initiate_heartbeat_timeout_shutdown(&self) {
        if let Err(e) = self.stop_client().await {
            error!("Failed to stop client during heartbeat timeout: {}", e);
        }

        info!("Attempting graceful shutdown via broadcast signal");
        match self.shutdown_tx.send(()) {
            Ok(receiver_count) => {
                info!("Shutdown signal sent to {} receivers", receiver_count);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                warn!("Failed to send shutdown signal (no receivers?): {}", e);
            }
        }

        error!("Forcing daemon exit due to heartbeat timeout");
        std::process::exit(1);
    }

    /// Handles an incoming IPC message and returns the appropriate response.
    ///
    /// # Arguments
    /// * `message` - The IPC message to process
    ///
    /// # Returns
    /// The response message to send back to the client
    async fn handle_message(&self, message: IpcMessage) -> IpcMessage {
        match message {
            IpcMessage::StartClient { config_path } => {
                self.handle_start_client_message(config_path).await
            }
            IpcMessage::StopClient => self.handle_stop_client_message().await,
            IpcMessage::GetStatus => {
                let status = self.get_status().await;
                IpcMessage::StatusUpdate(status)
            }
            IpcMessage::Shutdown => self.handle_shutdown_message().await,
            IpcMessage::Heartbeat => self.handle_heartbeat_message().await,
            _ => IpcMessage::Error("Invalid message".to_string()),
        }
    }

    /// Handles a StartClient IPC message.
    ///
    /// # Arguments
    /// * `config_path` - Path to the client configuration file
    ///
    /// # Returns
    /// Status update or error message
    async fn handle_start_client_message(&self, config_path: PathBuf) -> IpcMessage {
        match self.start_client(config_path, "QUINCY_").await {
            Ok(()) => {
                let status = self.get_status().await;
                IpcMessage::StatusUpdate(status)
            }
            Err(e) => IpcMessage::Error(e.to_string()),
        }
    }

    /// Handles a StopClient IPC message.
    ///
    /// # Returns
    /// Status update or error message
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
    ///
    /// # Returns
    /// Shutdown acknowledgment message
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

    /// Handles a Heartbeat IPC message.
    ///
    /// # Returns
    /// Heartbeat acknowledgment message
    async fn handle_heartbeat_message(&self) -> IpcMessage {
        debug!("Received heartbeat from GUI");
        *self.last_heartbeat.lock().await = Some(Instant::now());
        IpcMessage::HeartbeatAck
    }
}

impl Clone for ClientDaemon {
    /// Clones the ClientDaemon by sharing all Arc-wrapped fields.
    ///
    /// This enables multiple tasks to share access to the same daemon instance
    /// while maintaining thread safety through the Arc<Mutex<>> pattern.
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            connection_start_time: self.connection_start_time.clone(),
            instance_name: self.instance_name.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            last_heartbeat: self.last_heartbeat.clone(),
        }
    }
}

/// Main entry point for the Quincy client daemon.
///
/// This function initializes logging, creates a daemon instance, and runs the IPC server.
/// It handles graceful shutdown and cleanup when the daemon terminates.
///
/// # Returns
/// * `Ok(())` on successful completion
/// * `Err` if initialization or server startup fails
///
/// # Errors
/// Returns an error if:
/// - Logging setup fails
/// - IPC server cannot be started
/// - Socket cleanup fails
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    initialize_logging();

    info!("Starting Quincy client daemon: {}", args.instance_name);

    let daemon = ClientDaemon::new(args.instance_name.clone());
    let socket_path = get_ipc_socket_path(&args.instance_name);

    run_daemon_server(&daemon, &socket_path).await?;
    cleanup_socket(&socket_path);

    info!("Daemon shutdown complete");
    Ok(())
}

/// Initializes the logging system for the daemon.
fn initialize_logging() {
    let _logger = tracing::subscriber::set_global_default(log_subscriber("info"));
}

/// Runs the daemon IPC server until shutdown.
///
/// # Arguments
/// * `daemon` - The daemon instance to run
/// * `socket_path` - Path to the IPC socket
///
/// # Returns
/// Result of the server operation
///
/// # Errors
/// Returns an error if the IPC server fails to start or run
async fn run_daemon_server(daemon: &ClientDaemon, socket_path: &std::path::Path) -> Result<()> {
    info!("Starting IPC server...");
    daemon.run_ipc_server(socket_path).await?;
    info!("IPC server has stopped, proceeding with cleanup...");
    Ok(())
}

/// Cleans up the IPC socket file on shutdown.
///
/// # Arguments
/// * `socket_path` - Path to the socket file to remove
fn cleanup_socket(socket_path: &std::path::Path) {
    if socket_path.exists() {
        match std::fs::remove_file(socket_path) {
            Ok(()) => info!("Socket file removed: {:?}", socket_path),
            Err(e) => warn!("Failed to remove socket file on shutdown: {}", e),
        }
    }
}
