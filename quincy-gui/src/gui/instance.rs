use quincy::{QuincyError, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use super::types::QuincyInstance;
use crate::ipc::{
    get_ipc_socket_path, ClientStatus, ConnectionStatus, IpcConnection, IpcMessage, IpcServer,
};
use crate::privilege::run_elevated;

impl QuincyInstance {
    /// Starts a new Quincy VPN client instance.
    ///
    /// This method creates an IPC server, spawns a privileged daemon process,
    /// and waits for the daemon to connect.
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
    /// - IPC server cannot be created
    pub async fn start(name: String, config_path: PathBuf) -> Result<Self> {
        info!("Starting client daemon process for: {}", name);

        let socket_path = get_ipc_socket_path(&name);
        let ipc_server = IpcServer::new(&socket_path)?;

        let daemon_binary = Self::get_daemon_binary_path()?;
        Self::spawn_daemon_process(&daemon_binary, &config_path, &name).await?;

        let connection = ipc_server.accept().await?;
        let mut instance = Self::create_instance(name, Some(Arc::new(Mutex::new(connection))));

        instance.send_start_command(&config_path).await;
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
            .ok_or_else(|| QuincyError::system("Could not determine parent directory"))?
            .join("quincy-client-daemon"))
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
            return Err(QuincyError::system("Failed to spawn daemon process"));
        }

        Ok(())
    }

    /// Creates a new instance with the given parameters.
    ///
    /// # Arguments
    /// * `name` - Instance name
    /// * `ipc_connection` - IPC connection to daemon
    ///
    /// # Returns
    /// New QuincyInstance with default status
    fn create_instance(name: String, ipc_connection: Option<Arc<Mutex<IpcConnection>>>) -> Self {
        Self {
            name,
            ipc_client: ipc_connection,
            status: ClientStatus {
                status: ConnectionStatus::Disconnected,
                metrics: None,
            },
        }
    }

    /// Sends the start command to the daemon.
    ///
    /// # Arguments
    /// * `config_path` - Path to the configuration file
    async fn send_start_command(&self, config_path: &Path) {
        if let Some(ref ipc_connection) = self.ipc_client {
            let mut connection = ipc_connection.lock().await;
            if let Err(e) = connection
                .send(&IpcMessage::StartClient {
                    config_path: config_path.to_path_buf(),
                })
                .await
            {
                error!("Failed to send start command to daemon: {}", e);
            }
        }
    }

    /// Stops the VPN client instance and cleans up resources.
    ///
    /// This method gracefully shuts down the daemon process and updates the instance status.
    /// With the reversed architecture, the daemon will automatically detect disconnection
    /// when the GUI closes the IPC connection.
    ///
    /// # Returns
    /// * `Ok(())` if the instance was stopped successfully
    /// * `Err` if there were issues during shutdown (non-fatal)
    ///
    /// # Errors
    /// Returns an error if daemon communication fails, but continues with cleanup
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping client daemon process for: {}", self.name);

        self.send_shutdown_message().await;
        self.close_connection();
        self.reset_status();

        Ok(())
    }

    /// Sends a shutdown message to the daemon.
    async fn send_shutdown_message(&self) {
        if let Some(ref ipc_connection) = self.ipc_client {
            let mut connection = ipc_connection.lock().await;
            match connection.send(&IpcMessage::Shutdown).await {
                Ok(()) => info!("Sent graceful shutdown message to daemon"),
                Err(e) => warn!("Failed to send shutdown message to daemon: {}", e),
            }
        }
    }

    /// Closes the IPC connection to the daemon.
    fn close_connection(&mut self) {
        self.ipc_client = None;
        info!("IPC connection closed - daemon will detect disconnection");
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
        if let Some(ref ipc_connection) = self.ipc_client {
            let mut connection = ipc_connection.lock().await;
            match connection.send(&IpcMessage::GetStatus).await {
                Ok(()) => match connection.recv().await {
                    Ok(IpcMessage::StatusUpdate(status)) => {
                        drop(connection);
                        self.status = status.clone();
                    }
                    Ok(IpcMessage::Error(err)) => {
                        drop(connection);
                        self.set_error_status(&err);
                    }
                    Ok(_) => {
                        drop(connection);
                        warn!("Unexpected response to status request");
                    }
                    Err(e) => {
                        drop(connection);
                        warn!("Failed to receive status response: {}", e);
                        self.set_error_status("Status response failed");
                    }
                },
                Err(e) => {
                    drop(connection);
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
