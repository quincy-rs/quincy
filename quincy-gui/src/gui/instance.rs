use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use super::types::QuincyInstance;
use crate::ipc::{get_ipc_socket_path, ClientStatus, ConnectionStatus, IpcClient, IpcMessage};
use quincy::utils::privilege::run_elevated;

impl QuincyInstance {
    /// Starts a new Quincy VPN client instance.
    ///
    /// This method spawns a privileged daemon process, establishes IPC communication,
    /// and starts heartbeat monitoring.
    ///
    /// # Arguments
    /// * `name` - Unique identifier for this instance
    /// * `config_path` - Path to the VPN configuration file
    ///
    /// # Returns
    /// * `Ok(QuincyInstance)` if the instance started successfully
    /// * `Err` if the daemon process failed to start or IPC connection failed
    ///
    /// # Errors
    /// Returns an error if:
    /// - The daemon binary cannot be found
    /// - Elevated privileges cannot be obtained
    /// - IPC connection cannot be established
    pub async fn start(name: String, config_path: PathBuf) -> Result<Self> {
        info!("Starting client daemon process for: {}", name);

        let daemon_binary = Self::get_daemon_binary_path()?;
        Self::log_daemon_info();

        Self::spawn_daemon_process(&daemon_binary, &config_path, &name).await?;
        let ipc_client = Self::establish_ipc_connection(&name).await;

        let mut instance = Self::create_instance(name, ipc_client);
        instance.send_start_command(&config_path).await;
        instance.start_heartbeat_monitoring();
        instance.update_status().await?;

        Ok(instance)
    }

    /// Gets the path to the daemon binary.
    ///
    /// # Returns
    /// Path to the quincy-client-daemon binary
    ///
    /// # Errors
    /// Returns an error if the current executable path cannot be determined
    fn get_daemon_binary_path() -> Result<PathBuf> {
        Ok(std::env::current_exe()?
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Could not determine parent directory"))?
            .join("quincy-client-daemon"))
    }

    /// Logs information about daemon log file locations.
    fn log_daemon_info() {
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let log_dir = std::path::Path::new(&home_dir).join(".quincy");
        info!("Daemon logs will be available at:");
        info!("  stdout: {}/daemon-stdout.log", log_dir.display());
        info!("  stderr: {}/daemon-stderr.log", log_dir.display());
    }

    /// Spawns the daemon process with elevated privileges.
    ///
    /// # Arguments
    /// * `daemon_binary` - Path to the daemon executable
    /// * `config_path` - Path to the configuration file
    /// * `name` - Instance name
    ///
    /// # Returns
    /// Result indicating if privilege escalation succeeded
    ///
    /// # Errors
    /// Returns an error if the privilege escalation process fails
    async fn spawn_daemon_process(
        daemon_binary: &Path,
        config_path: &Path,
        name: &str,
    ) -> Result<()> {
        let child = run_elevated(
            &daemon_binary.to_string_lossy(),
            &[
                "--config-path",
                &config_path.to_string_lossy(),
                "--instance-name",
                name,
            ],
            "Quincy VPN Client",
            "Quincy needs administrator privileges to create network interfaces.",
        )?;

        let elevation_result =
            tokio::task::spawn_blocking(move || child.wait_with_output()).await??;

        if !elevation_result.status.success() || !elevation_result.stderr.is_empty() {
            return Err(anyhow!("Failed to spawn daemon process"));
        }

        Ok(())
    }

    /// Establishes IPC connection to the daemon with retry logic.
    ///
    /// # Arguments
    /// * `name` - Instance name for socket path generation
    ///
    /// # Returns
    /// IPC client wrapped in Arc<Mutex> for thread safety
    async fn establish_ipc_connection(name: &str) -> Option<Arc<Mutex<IpcClient>>> {
        let socket_path = get_ipc_socket_path(name);
        info!("Attempting to connect to daemon at: {:?}", socket_path);

        loop {
            tokio::time::sleep(Duration::from_millis(1000)).await;

            let Ok(client) = IpcClient::connect(&socket_path).await else {
                continue;
            };

            info!("Successfully connected to daemon");
            return Some(Arc::new(Mutex::new(client)));
        }
    }

    /// Creates a new instance with the given parameters.
    ///
    /// # Arguments
    /// * `name` - Instance name
    /// * `child` - Daemon process handle
    /// * `ipc_client` - IPC client connection
    ///
    /// # Returns
    /// New QuincyInstance with default status
    fn create_instance(name: String, ipc_client: Option<Arc<Mutex<IpcClient>>>) -> Self {
        Self {
            name,
            ipc_client,
            status: ClientStatus {
                status: ConnectionStatus::Disconnected,
                metrics: None,
            },
            heartbeat_handle: None,
        }
    }

    /// Sends the start command to the daemon.
    ///
    /// # Arguments
    /// * `config_path` - Path to the configuration file
    async fn send_start_command(&self, config_path: &Path) {
        if let Some(ref ipc_client) = self.ipc_client {
            let mut client = ipc_client.lock().await;
            if let Err(e) = client
                .send(&IpcMessage::StartClient {
                    config_path: config_path.to_path_buf(),
                })
                .await
            {
                error!("Failed to send start command to daemon: {}", e);
            }
        }
    }

    /// Starts the heartbeat monitoring task.
    fn start_heartbeat_monitoring(&mut self) {
        if let Some(ref ipc_client) = self.ipc_client {
            let heartbeat_client = ipc_client.clone();
            let instance_name = self.name.clone();
            let handle = tokio::spawn(async move {
                Self::heartbeat_task(heartbeat_client, instance_name).await;
            });
            self.heartbeat_handle = Some(handle);
        }
    }

    /// Background task that sends periodic heartbeat messages to the daemon.
    ///
    /// This ensures the daemon knows the GUI is still running and can shut down
    /// gracefully if the GUI process terminates unexpectedly.
    ///
    /// # Arguments
    /// * `ipc_client` - Shared IPC client connection
    /// * `instance_name` - Name of the instance for logging
    async fn heartbeat_task(ipc_client: Arc<Mutex<IpcClient>>, instance_name: String) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);

        loop {
            interval.tick().await;

            let mut client = match ipc_client.try_lock() {
                Ok(client) => client,
                Err(_) => continue, // Client is busy, skip this heartbeat
            };

            if Self::send_heartbeat_and_wait_response(
                &mut client,
                &instance_name,
                HEARTBEAT_TIMEOUT,
            )
            .await
            .is_err()
            {
                break;
            }
        }

        info!("Heartbeat task stopped for {}", instance_name);
    }

    /// Sends a heartbeat message and waits for acknowledgment.
    ///
    /// # Arguments
    /// * `client` - IPC client to use for communication
    /// * `instance_name` - Instance name for logging
    /// * `timeout_duration` - Maximum time to wait for response
    ///
    /// # Returns
    /// * `Ok(())` if heartbeat was acknowledged
    /// * `Err(())` if heartbeat failed or timed out
    async fn send_heartbeat_and_wait_response(
        client: &mut IpcClient,
        instance_name: &str,
        timeout_duration: Duration,
    ) -> Result<(), ()> {
        let Err(e) = client.send(&IpcMessage::Heartbeat).await else {
            return Self::handle_heartbeat_response(client, instance_name, timeout_duration).await;
        };

        warn!("Failed to send heartbeat for {}: {}", instance_name, e);
        Err(())
    }

    /// Handles the response to a heartbeat message.
    ///
    /// # Arguments
    /// * `client` - IPC client to receive response from
    /// * `instance_name` - Instance name for logging
    /// * `timeout_duration` - Maximum time to wait for response
    ///
    /// # Returns
    /// * `Ok(())` if valid acknowledgment received
    /// * `Err(())` if invalid response or timeout
    async fn handle_heartbeat_response(
        client: &mut IpcClient,
        instance_name: &str,
        timeout_duration: Duration,
    ) -> Result<(), ()> {
        match timeout(timeout_duration, client.recv()).await {
            Ok(Ok(IpcMessage::HeartbeatAck)) => {
                debug!("Heartbeat acknowledged for {}", instance_name);
                Ok(())
            }
            Ok(Ok(_)) => {
                warn!("Unexpected response to heartbeat for {}", instance_name);
                Err(())
            }
            Ok(Err(e)) => {
                warn!("Heartbeat communication error for {}: {}", instance_name, e);
                Err(())
            }
            Err(_) => {
                warn!("Heartbeat timeout for {}", instance_name);
                Err(())
            }
        }
    }

    /// Stops the VPN client instance and cleans up resources.
    ///
    /// This method gracefully shuts down the daemon process, stops heartbeat monitoring,
    /// and updates the instance status.
    ///
    /// # Returns
    /// * `Ok(())` if the instance was stopped successfully
    /// * `Err` if there were issues during shutdown (non-fatal)
    ///
    /// # Errors
    /// Returns an error if daemon communication fails, but continues with cleanup
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping client daemon process for: {}", self.name);

        self.stop_heartbeat_task();
        self.send_shutdown_message().await;
        self.reset_status();

        Ok(())
    }

    /// Stops the heartbeat monitoring task.
    fn stop_heartbeat_task(&mut self) {
        if let Some(handle) = self.heartbeat_handle.take() {
            handle.abort();
            info!("Heartbeat task stopped");
        }
    }

    /// Sends a shutdown message to the daemon.
    async fn send_shutdown_message(&self) {
        if let Some(ref ipc_client) = self.ipc_client {
            let mut client = ipc_client.lock().await;
            match client.send(&IpcMessage::Shutdown).await {
                Ok(()) => info!("Sent graceful shutdown message to daemon"),
                Err(e) => warn!("Failed to send shutdown message to daemon: {}", e),
            }
        }
    }

    /// Resets the instance status to disconnected.
    fn reset_status(&mut self) {
        self.status = ClientStatus {
            status: ConnectionStatus::Disconnected,
            metrics: None,
        };
    }

    /// Updates the current status and metrics from the daemon.
    ///
    /// # Returns
    /// * `Ok(())` if status was updated successfully
    /// * `Err` if IPC communication failed
    ///
    /// # Errors
    /// Returns an error if the daemon cannot be contacted or responds with invalid data
    pub async fn update_status(&mut self) -> Result<()> {
        if let Some(ref ipc_client) = self.ipc_client {
            let mut client = ipc_client.lock().await;
            match client.send(&IpcMessage::GetStatus).await {
                Ok(()) => match client.recv().await {
                    Ok(IpcMessage::StatusUpdate(status)) => {
                        drop(client);
                        self.status = status;
                    }
                    Ok(IpcMessage::Error(err)) => {
                        drop(client);
                        self.set_error_status(&err);
                    }
                    Ok(_) => {
                        drop(client);
                        warn!("Unexpected response to status request");
                    }
                    Err(e) => {
                        drop(client);
                        warn!("Failed to receive status response: {}", e);
                        self.set_error_status("Status response failed");
                    }
                },
                Err(e) => {
                    drop(client);
                    warn!("Failed to get status from daemon: {}", e);
                    self.set_error_status("IPC communication failed");
                }
            }
        }
        Ok(())
    }

    /// Sets the status to an error state with the given message.
    ///
    /// # Arguments
    /// * `error_message` - Error description to display
    fn set_error_status(&mut self, error_message: &str) {
        self.status = ClientStatus {
            status: ConnectionStatus::Error(error_message.to_string()),
            metrics: None,
        };
    }

    /// Gets the current status of this VPN instance.
    ///
    /// # Returns
    /// Reference to the current client status including connection state and metrics
    pub fn get_status(&self) -> &ClientStatus {
        &self.status
    }
}
