use privesc::{PrivilegedChild, PrivilegedCommand};
use quincy::{QuincyError, Result};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{error, info, warn};

use super::types::QuincyInstance;
use crate::ipc::{
    get_ipc_socket_path, get_log_file_path, ConnectionMetrics, ConnectionStatus, IpcMessage,
    IpcServer,
};
use crate::validation;

impl QuincyInstance {
    /// Maximum duration to wait for the daemon to establish the IPC connection.
    const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(15);

    /// Starts a new Quincy VPN client instance.
    ///
    /// This method creates an IPC server, spawns a privileged daemon process,
    /// and waits for the daemon to connect. The daemon will then start
    /// connecting to the VPN server while listening for cancellation messages.
    ///
    /// # Arguments
    /// * `name` - Unique identifier for this instance
    /// * `config_path` - Path to the VPN configuration file
    ///
    /// # Returns
    /// * `Ok((QuincyInstance, Option<ConnectionMetrics>))` if the instance started successfully
    /// * `Err` if the daemon process failed to start or IPC connection failed
    ///
    /// # Errors
    /// Returns an error if:
    /// - The daemon binary cannot be found
    /// - Elevated privileges cannot be obtained
    /// - IPC server cannot be created
    pub async fn start(
        name: String,
        config_path: PathBuf,
    ) -> Result<(Self, Option<ConnectionMetrics>)> {
        // Validate instance/config name early to avoid spawning processes with unsafe names
        validation::validate_instance_name(&name)?;
        info!("Starting client daemon process for: {}", name);

        let socket_path = get_ipc_socket_path(&name);
        let log_path = get_log_file_path(&name);
        let ipc_server = IpcServer::new(&socket_path)?;

        let daemon_binary = Self::get_daemon_binary_path()?;
        let handle = Self::spawn_daemon_process(
            &daemon_binary,
            &name,
            &config_path,
            &socket_path,
            &log_path,
        )?;

        let connection = match timeout(Self::DAEMON_START_TIMEOUT, ipc_server.accept()).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                warn!(
                    "Timed out after {:?} while waiting for daemon IPC connection",
                    Self::DAEMON_START_TIMEOUT
                );
                return Err(QuincyError::system(Self::get_spawn_error(handle)));
            }
        };

        let instance = Self::new(name, Some(Arc::new(Mutex::new(connection))));

        // Send start command - daemon will now start VPN connection
        // and listen for IPC messages (including Shutdown for cancellation)
        instance.send_start_command(&config_path).await;
        let metrics = instance.fetch_initial_status().await?;

        Ok((instance, metrics))
    }

    /// Gets the path to the daemon binary.
    fn get_daemon_binary_path() -> Result<PathBuf> {
        Ok(env::current_exe()?
            .parent()
            .ok_or_else(|| QuincyError::system("Could not determine parent directory"))?
            .join("quincy-client-daemon"))
    }

    /// Spawns the daemon process with elevated privileges.
    /// Returns PrivilegedChild for error diagnostics.
    fn spawn_daemon_process(
        daemon_binary: &Path,
        name: &str,
        config_path: &Path,
        socket_path: &Path,
        log_path: &Path,
    ) -> Result<PrivilegedChild> {
        // Convert paths to strings - no manual quoting needed since we pass args directly
        let binary_str = daemon_binary.to_string_lossy();
        let config_str = config_path.to_string_lossy();
        let socket_str = socket_path.to_string_lossy();
        let log_str = log_path.to_string_lossy();

        // Build argument list to pass directly to privilege escalation tools
        // Arguments are passed as-is without shell interpretation
        let args: [&str; 8] = [
            "--instance-name",
            name,
            "--config-path",
            &config_str,
            "--socket-path",
            &socket_str,
            "--log-path",
            &log_str,
        ];

        PrivilegedCommand::new(binary_str)
            .args(args)
            .gui(true)
            .prompt("Quincy needs administrator privileges to create network interfaces.")
            .spawn()
            .map_err(|err| QuincyError::system(format!("{err}")))
    }

    /// Extracts error information from a failed daemon spawn attempt.
    fn get_spawn_error(mut handle: PrivilegedChild) -> String {
        // If the child process has not exited yet
        if handle.try_wait().ok().flatten().is_none() {
            return "Timed out waiting for daemon IPC connection".to_string();
        }

        // We know wait will not block because try_wait() returned Some(status)
        let Some(output) = handle.wait().ok() else {
            return "Timed out waiting for daemon IPC connection".to_string();
        };

        if output.status.success() {
            return "Timed out waiting for daemon IPC connection".to_string();
        }

        match output.stderr_str() {
            Some(stderr) if !stderr.is_empty() => {
                format!("Daemon process failed: {}", stderr.trim())
            }
            _ => format!("Daemon process exited with status: {}", output.status),
        }
    }

    /// Sends the start command to the daemon.
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

    /// Fetches the initial status and metrics from the daemon.
    ///
    /// # Returns
    /// * `Ok(Some(metrics))` if connected with metrics
    /// * `Ok(None)` if connected without metrics (still connecting)
    /// * `Err` if daemon reports an error or communication fails
    async fn fetch_initial_status(&self) -> Result<Option<ConnectionMetrics>> {
        let Some(ref ipc_connection) = self.ipc_client else {
            return Ok(None);
        };

        let mut connection = ipc_connection.lock().await;

        connection.send(&IpcMessage::GetStatus).await?;

        match connection.recv().await? {
            IpcMessage::StatusUpdate(status) => match status.status {
                ConnectionStatus::Connected => Ok(status.metrics),
                ConnectionStatus::Connecting => Ok(None),
                ConnectionStatus::Disconnected => Err(QuincyError::system("Daemon disconnected")),
                ConnectionStatus::Error(err) => Err(QuincyError::system(err.to_string())),
            },
            IpcMessage::Error(err) => Err(QuincyError::system(err.to_string())),
            other => {
                warn!("Unexpected response to status request: {:?}", other);
                Ok(None)
            }
        }
    }

    /// Stops the VPN client instance and cleans up resources.
    ///
    /// # Returns
    /// * `Ok(())` if the instance was stopped successfully
    /// * `Err` if there were issues during shutdown (non-fatal)
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping client daemon process for: {}", self.name);

        self.send_shutdown_message().await;
        self.close_connection();

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
}
