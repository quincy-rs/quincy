use quincy::{QuincyError, Result};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;
use tokio::time::timeout;
use tracing::{error, info, warn};

use super::types::QuincyInstance;
use crate::ipc::{get_ipc_socket_path, ConnectionMetrics, ConnectionStatus, IpcMessage, IpcServer};
use crate::privilege::run_elevated;
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
        let ipc_server = IpcServer::new(&socket_path)?;

        let daemon_binary = Self::get_daemon_binary_path()?;
        Self::spawn_daemon_process(&daemon_binary, &config_path, &name).await?;

        let connection = match timeout(Self::DAEMON_START_TIMEOUT, ipc_server.accept()).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                warn!(
                    "Timed out after {:?} while waiting for daemon IPC connection",
                    Self::DAEMON_START_TIMEOUT
                );
                return Err(QuincyError::system(
                    "Timed out waiting for daemon IPC connection",
                ));
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
    async fn spawn_daemon_process(
        daemon_binary: &Path,
        config_path: &Path,
        name: &str,
    ) -> Result<()> {
        let quoted_binary = Self::quote_for_cmdline(&daemon_binary.to_string_lossy());
        let quoted_config = Self::quote_for_cmdline(&config_path.to_string_lossy());
        let quoted_name = Self::quote_for_cmdline(name);

        let args: [&str; 4] = [
            "--config-path",
            quoted_config.as_str(),
            "--instance-name",
            quoted_name.as_str(),
        ];

        let child = run_elevated(
            &quoted_binary,
            &args,
            "Quincy VPN Client",
            "Quincy needs administrator privileges to create network interfaces.",
        )?;

        let elevation_result = spawn_blocking(move || child.wait_with_output()).await??;

        if !elevation_result.status.success() || !elevation_result.stderr.is_empty() {
            return Err(QuincyError::system("Failed to spawn daemon process"));
        }

        Ok(())
    }

    /// Wraps an argument in double quotes and escapes any embedded double quotes.
    fn quote_for_cmdline(arg: &str) -> String {
        let mut out = String::with_capacity(arg.len() + 2);
        out.push('"');
        for ch in arg.chars() {
            if ch == '"' {
                out.push('\\');
                out.push('"');
            } else {
                out.push(ch);
            }
        }
        out.push('"');
        out
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
                ConnectionStatus::Error(err) => Err(QuincyError::system(err)),
            },
            IpcMessage::Error(err) => Err(QuincyError::system(err)),
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
