use crate::ipc::{
    get_ipc_socket_path, ClientStatus, ConnectionMetrics, ConnectionStatus, IpcClient, IpcMessage,
};
use anyhow::{anyhow, Result};
use dashmap::DashMap;
use iced::alignment::Horizontal;
use iced::widget::button::{danger, primary, secondary};
use iced::widget::container::Style;
use iced::widget::{button, column, container, row, scrollable, text, text_editor, text_input};
use iced::{border, highlighter, Element, Length, Task, Theme};
use quincy::utils::privilege::run_elevated;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Represents a running Quincy VPN client instance.
///
/// Each instance manages a daemon process, IPC communication, and heartbeat monitoring.
/// The instance tracks connection status and metrics for display in the GUI.
pub struct QuincyInstance {
    /// Unique identifier for this instance
    pub name: String,
    /// IPC client for communication with the daemon
    ipc_client: Option<Arc<Mutex<IpcClient>>>,
    /// Current connection status and metrics
    status: ClientStatus,
    /// Handle to the heartbeat monitoring task
    heartbeat_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Debug for QuincyInstance {
    /// Custom Debug implementation that excludes process handles and other non-debuggable fields.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuincyInstance")
            .field("name", &self.name)
            .field("status", &self.status)
            .finish()
    }
}

/// Configuration file information for a Quincy VPN client.
#[derive(Clone)]
pub struct QuincyConfig {
    /// Display name of the configuration
    pub name: String,
    /// File system path to the configuration file
    pub path: PathBuf,
}

/// Container for a selected configuration and its editable content.
pub struct SelectedConfig {
    /// The configuration metadata
    pub quincy_config: QuincyConfig,
    /// The text editor content for the configuration file
    pub editable_content: text_editor::Content,
}

/// Main GUI application state for the Quincy VPN client.
///
/// This structure manages configuration files, running VPN instances,
/// and the user interface state. It provides a graphical interface
/// for managing multiple VPN configurations and connections.
pub struct QuincyGui {
    /// Directory containing configuration files
    config_dir: PathBuf,
    /// Available VPN configurations indexed by name
    configs: HashMap<String, QuincyConfig>,
    /// Currently running VPN instances
    instances: Arc<DashMap<String, QuincyInstance>>,
    /// Currently selected configuration for editing
    selected_config: Option<SelectedConfig>,
}

/// Messages for GUI state updates and user interactions.
#[derive(Debug, Clone)]
pub enum Message {
    /// User selected a configuration from the list
    ConfigSelected(String),
    /// User edited the configuration text
    ConfigEdited(text_editor::Action),
    /// User changed the configuration name
    ConfigNameChanged(String),
    /// User saved the configuration name change
    ConfigNameSaved,
    /// User requested to save the configuration
    ConfigSave,
    /// User requested to delete the configuration
    ConfigDelete,
    /// User requested to create a new configuration
    NewConfig,
    /// User requested to connect to a VPN
    Connect,
    /// VPN connection was established
    Connected(String),
    /// User requested to disconnect from VPN
    Disconnect,
    /// VPN was disconnected
    Disconnected,
    /// Periodic update of connection metrics
    UpdateMetrics,
}

impl QuincyGui {
    /// Creates a new QuincyGui application instance.
    ///
    /// This method initializes the application with the provided configuration directory,
    /// setting up and loading existing configurations.
    ///
    /// # Arguments
    /// * `config_dir` - Path to the configuration directory
    ///
    /// # Returns
    /// A tuple containing the GUI instance and initial task to run
    ///
    /// # Panics
    /// Panics if critical initialization fails (config directory setup or loading)
    pub fn new(config_dir: PathBuf) -> (Self, Task<Message>) {
        if let Err(e) = Self::validate_and_create_config_dir(&config_dir) {
            error!("Failed to set up config directory: {}", e);
            std::process::exit(1);
        }

        let configs = match Self::load_configurations(&config_dir) {
            Ok(configs) => configs,
            Err(e) => {
                error!("Failed to load configurations: {}", e);
                std::process::exit(1);
            }
        };

        (
            Self {
                config_dir,
                configs,
                instances: Arc::new(DashMap::new()),
                selected_config: None,
            },
            Task::done(Message::UpdateMetrics),
        )
    }

    /// Returns the window title for the application.
    ///
    /// # Returns
    /// Static title string
    pub fn title(&self) -> String {
        String::from("Quincy VPN Client")
    }

    /// Returns the theme to use for the application.
    ///
    /// # Returns
    /// Currently always returns Dark theme
    pub fn theme(&self) -> Theme {
        // TODO: theme selector
        Theme::Dark
    }

    /// Processes GUI messages and updates application state.
    ///
    /// This method handles all user interactions and system events,
    /// delegating to specific handler methods for better organization.
    ///
    /// # Arguments
    /// * `message` - The message to process
    ///
    /// # Returns
    /// Task to execute as a result of processing the message
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ConfigSelected(name) => self.handle_config_selected(name),
            Message::ConfigEdited(action) => self.handle_config_edited(action),
            Message::ConfigNameChanged(new_name) => self.handle_config_name_changed(new_name),
            Message::ConfigNameSaved => self.handle_config_name_saved(),
            Message::ConfigSave => self.handle_config_save(),
            Message::ConfigDelete => self.handle_config_delete(),
            Message::NewConfig => self.handle_new_config(),
            Message::Connect => self.handle_connect(),
            Message::Disconnect => self.handle_disconnect(),
            Message::Connected(_config_name) => {
                // Instance was already inserted during the async task
                Task::none()
            }
            Message::Disconnected => Task::none(),
            Message::UpdateMetrics => self.handle_update_metrics(),
        }
    }

    /// Builds the main user interface view.
    ///
    /// This method creates the complete GUI layout with a left panel for
    /// configuration selection and a right panel for editing and monitoring.
    ///
    /// # Returns
    /// Complete UI element tree for the application
    pub fn view(&self) -> Element<Message> {
        let left_panel = self.build_config_selection_panel();
        let right_panel = self.build_config_details_panel();

        container(row![left_panel, right_panel].spacing(10).padding(20))
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }
}

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

impl QuincyGui {
    /// Validates the config directory path and creates it if necessary.
    ///
    /// # Arguments
    /// * `config_dir` - Path to the configuration directory
    ///
    /// # Returns
    /// * `Ok(())` if the directory is valid or was created successfully
    /// * `Err` if the path is invalid or directory creation fails
    ///
    /// # Errors
    /// Returns an error if:
    /// - The config path points to an existing file instead of a directory
    /// - The directory cannot be created due to permissions or other I/O errors
    fn validate_and_create_config_dir(config_dir: &Path) -> Result<()> {
        if config_dir.is_file() {
            return Err(anyhow::anyhow!(
                "Config directory path points to a file: {}",
                config_dir.display()
            ));
        }

        if !config_dir.exists() {
            fs::create_dir_all(config_dir).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create config directory {}: {}",
                    config_dir.display(),
                    e
                )
            })?
        }

        Ok(())
    }

    /// Loads all configuration files from the config directory.
    ///
    /// # Arguments
    /// * `config_dir` - Path to the configuration directory
    ///
    /// # Returns
    /// * `Ok(HashMap)` of configuration name to QuincyConfig
    /// * `Err` if the config directory cannot be read
    ///
    /// # Errors
    /// Returns an error if the config directory cannot be read due to
    /// permissions or I/O issues
    fn load_configurations(config_dir: &Path) -> Result<HashMap<String, QuincyConfig>> {
        let entries = fs::read_dir(config_dir)
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read config directory {}: {}",
                    config_dir.display(),
                    e
                )
            })?
            .filter_map(Self::process_config_entry)
            .collect();

        Ok(entries)
    }

    /// Processes a single configuration file entry.
    ///
    /// # Arguments
    /// * `entry` - Directory entry result
    ///
    /// # Returns
    /// Optional tuple of (config_name, QuincyConfig)
    fn process_config_entry(
        entry: Result<fs::DirEntry, std::io::Error>,
    ) -> Option<(String, QuincyConfig)> {
        let config_path = entry.ok()?.path();

        // Only process .toml files
        if !config_path.extension().is_some_and(|ext| ext == "toml") {
            return None;
        }

        let config_file_name = config_path.file_name()?.to_string_lossy().to_string();

        let config_name = config_file_name
            .to_lowercase()
            .strip_suffix(".toml")
            .unwrap_or(&config_file_name)
            .to_string();

        let loaded_config = QuincyConfig {
            name: config_name.clone(),
            path: config_path,
        };

        Some((config_name, loaded_config))
    }

    /// Handles selection of a configuration from the list.
    ///
    /// # Arguments
    /// * `name` - Name of the configuration to select
    ///
    /// # Returns
    /// Task::none() - No async task needed
    fn handle_config_selected(&mut self, name: String) -> Task<Message> {
        let Some(config) = self.configs.get(&name) else {
            error!("Configuration not found: {name}");
            return Task::none();
        };

        match self.load_config_content(config) {
            Ok(selected_config) => {
                self.selected_config = Some(selected_config);
                info!("Config selected: {name}");
            }
            Err(e) => {
                error!("Failed to read config file: {}", e);
            }
        }
        Task::none()
    }

    /// Loads the content of a configuration file.
    ///
    /// # Arguments
    /// * `config` - Configuration to load
    ///
    /// # Returns
    /// Result containing SelectedConfig or IO error
    fn load_config_content(&self, config: &QuincyConfig) -> Result<SelectedConfig> {
        let config_content = fs::read_to_string(&config.path)?;
        let editable_content = text_editor::Content::with_text(&config_content);

        Ok(SelectedConfig {
            quincy_config: config.clone(),
            editable_content,
        })
    }

    /// Handles editing of the configuration text.
    ///
    /// # Arguments
    /// * `action` - Text editor action to perform
    ///
    /// # Returns
    /// Task::none() - No async task needed
    fn handle_config_edited(&mut self, action: text_editor::Action) -> Task<Message> {
        if let Some(selected_config) = self.selected_config.as_mut() {
            selected_config.editable_content.perform(action);
        } else {
            error!("No configuration selected");
        }
        Task::none()
    }

    /// Handles changes to the configuration name.
    ///
    /// # Arguments
    /// * `new_name` - New name for the configuration
    ///
    /// # Returns
    /// Task::none() - No async task needed
    fn handle_config_name_changed(&mut self, new_name: String) -> Task<Message> {
        if let Some(selected_config) = self.selected_config.as_mut() {
            selected_config.quincy_config.name = new_name;
        } else {
            error!("No configuration selected");
        }
        Task::none()
    }

    /// Handles saving of a renamed configuration.
    ///
    /// # Returns
    /// Task::none() - No async task needed
    fn handle_config_name_saved(&mut self) -> Task<Message> {
        let old_config_name = {
            let Some(ref selected_config) = self.selected_config else {
                error!("No configuration selected");
                return Task::none();
            };

            let Some(old_config_name) = self.extract_old_config_name(selected_config) else {
                return Task::none();
            };
            old_config_name
        };

        // Extract the selected config to avoid borrowing conflicts
        let Some(mut selected_config) = self.selected_config.take() else {
            return Task::none();
        };

        self.rename_config_file(&mut selected_config, &old_config_name);
        self.selected_config = Some(selected_config);
        Task::none()
    }

    /// Extracts the old configuration name from the file path.
    ///
    /// # Arguments
    /// * `selected_config` - Currently selected configuration
    ///
    /// # Returns
    /// Optional old configuration name
    fn extract_old_config_name(&self, selected_config: &SelectedConfig) -> Option<String> {
        let file_name = selected_config
            .quincy_config
            .path
            .file_name()?
            .to_string_lossy()
            .to_string();

        Some(
            file_name
                .to_lowercase()
                .strip_suffix(".toml")
                .unwrap_or(&file_name)
                .to_string(),
        )
    }

    /// Renames a configuration file and updates internal state.
    ///
    /// # Arguments
    /// * `selected_config` - Configuration being renamed
    /// * `old_config_name` - Previous name of the configuration
    fn rename_config_file(&mut self, selected_config: &mut SelectedConfig, old_config_name: &str) {
        self.configs.remove(old_config_name);

        let old_path = selected_config.quincy_config.path.clone();
        let new_path = self
            .config_dir
            .join(format!("{}.toml", selected_config.quincy_config.name));

        self.save_config_to_new_path(selected_config, &new_path);
        self.remove_old_config_file(&old_path);

        self.configs.insert(
            selected_config.quincy_config.name.clone(),
            selected_config.quincy_config.clone(),
        );
    }

    /// Saves configuration content to a new file path.
    ///
    /// # Arguments
    /// * `selected_config` - Configuration to save
    /// * `new_path` - New file path
    fn save_config_to_new_path(&mut self, selected_config: &mut SelectedConfig, new_path: &Path) {
        match fs::write(new_path, selected_config.editable_content.text()) {
            Ok(_) => {
                info!("Config file saved: {}", new_path.display());
                selected_config.quincy_config.path = new_path.to_path_buf();
            }
            Err(e) => {
                error!("Failed to save config file: {}", e);
            }
        }
    }

    /// Removes the old configuration file.
    ///
    /// # Arguments
    /// * `old_path` - Path to the old configuration file
    fn remove_old_config_file(&self, old_path: &Path) {
        match fs::remove_file(old_path) {
            Ok(_) => info!("Old config file removed: {}", old_path.display()),
            Err(e) => error!("Failed to remove old config file: {}", e),
        }
    }

    /// Handles saving of the current configuration.
    ///
    /// # Returns
    /// Task::none() - No async task needed
    fn handle_config_save(&mut self) -> Task<Message> {
        let selected_config = match self.selected_config.as_mut() {
            Some(config) => config,
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        let config_content = selected_config.editable_content.text();

        self.configs.insert(
            selected_config.quincy_config.name.clone(),
            selected_config.quincy_config.clone(),
        );

        match fs::write(&selected_config.quincy_config.path, config_content) {
            Ok(_) => {
                info!(
                    "Config file saved: {}",
                    selected_config.quincy_config.path.display()
                );
            }
            Err(e) => {
                error!("Failed to save config file: {}", e);
            }
        }

        Task::none()
    }

    /// Handles deletion of the current configuration.
    ///
    /// # Returns
    /// Task::none() - No async task needed
    fn handle_config_delete(&mut self) -> Task<Message> {
        let selected_config = match self.selected_config.take() {
            Some(config) => config,
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        match fs::remove_file(&selected_config.quincy_config.path) {
            Ok(_) => {
                info!(
                    "Config file deleted: {}",
                    selected_config.quincy_config.path.display()
                );
            }
            Err(e) => {
                error!("Failed to delete config file: {}", e);
            }
        }

        self.configs.remove(&selected_config.quincy_config.name);
        Task::none()
    }

    /// Handles creation of a new configuration.
    ///
    /// # Returns
    /// Task::none() - No async task needed
    fn handle_new_config(&mut self) -> Task<Message> {
        let new_config_name = self.generate_unique_config_name();
        let new_config = self.create_new_config(&new_config_name);
        let selected_config = self.create_selected_config_with_template(new_config.clone());

        self.save_new_config_file(&selected_config);

        self.selected_config = Some(selected_config);
        self.configs.insert(new_config_name, new_config);

        Task::none()
    }

    /// Generates a unique name for a new configuration.
    ///
    /// # Returns
    /// Unique configuration name
    fn generate_unique_config_name(&self) -> String {
        let mut config_idx = 0;
        let mut new_config_name = "client_config".to_string();

        while self.configs.contains_key(&new_config_name) {
            config_idx += 1;
            new_config_name = format!("client_config_{}", config_idx);
        }

        new_config_name
    }

    /// Creates a new QuincyConfig with the given name.
    ///
    /// # Arguments
    /// * `name` - Name for the new configuration
    ///
    /// # Returns
    /// New QuincyConfig instance
    fn create_new_config(&self, name: &str) -> QuincyConfig {
        QuincyConfig {
            name: name.to_string(),
            path: self.config_dir.join(format!("{name}.toml")),
        }
    }

    /// Creates a SelectedConfig with a template configuration.
    ///
    /// # Arguments
    /// * `config` - Base configuration
    ///
    /// # Returns
    /// SelectedConfig with template content
    fn create_selected_config_with_template(&self, config: QuincyConfig) -> SelectedConfig {
        SelectedConfig {
            quincy_config: config,
            editable_content: text_editor::Content::with_text(include_str!(
                "../../examples/client.toml"
            )),
        }
    }

    /// Saves a new configuration file to disk.
    ///
    /// # Arguments
    /// * `selected_config` - Configuration to save
    fn save_new_config_file(&self, selected_config: &SelectedConfig) {
        match fs::write(
            &selected_config.quincy_config.path,
            selected_config.editable_content.text(),
        ) {
            Ok(_) => {
                info!(
                    "Config file saved: {}",
                    selected_config.quincy_config.path.display()
                );
            }
            Err(e) => {
                error!("Failed to save config file: {}", e);
            }
        }
    }

    /// Handles VPN connection request.
    ///
    /// # Returns
    /// Async task to establish the VPN connection
    fn handle_connect(&mut self) -> Task<Message> {
        let selected_config = match self.selected_config.as_mut() {
            Some(config) => config,
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        let config_name = selected_config.quincy_config.name.clone();
        let config_path = selected_config.quincy_config.path.clone();
        let instances = self.instances.clone();

        Task::future(async move {
            info!("Connecting to instance: {}", config_name);

            match QuincyInstance::start(config_name.clone(), config_path).await {
                Ok(instance) => {
                    info!("Instance {} connected", config_name);
                    instances.insert(config_name.clone(), instance);
                    Message::Connected(config_name)
                }
                Err(e) => {
                    error!("Failed to start Quincy instance: {}", e);
                    Message::Disconnected
                }
            }
        })
    }

    /// Handles VPN disconnection request.
    ///
    /// # Returns
    /// Async task to disconnect from the VPN
    fn handle_disconnect(&mut self) -> Task<Message> {
        let instance_config = match &self.selected_config {
            Some(config) => config.quincy_config.clone(),
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        let mut client_instance = match self.instances.remove(&instance_config.name) {
            Some((_, client)) => client,
            None => {
                error!(
                    "No client instance found for configuration: {}",
                    instance_config.name
                );
                return Task::none();
            }
        };

        info!("Instance {} disconnected", instance_config.name);

        Task::future(async move {
            match client_instance.stop().await {
                Ok(_) => info!("Instance {} disconnected", instance_config.name),
                Err(e) => error!("Failed to stop client instance: {}", e),
            }

            Message::Disconnected
        })
    }

    /// Handles periodic metrics updates for all running instances.
    ///
    /// # Returns
    /// Async task to update metrics and schedule the next update
    fn handle_update_metrics(&self) -> Task<Message> {
        let instances = self.instances.clone();

        Task::future(async move {
            for mut entry in instances.iter_mut() {
                let instance = entry.value_mut();
                if let Err(e) = instance.update_status().await {
                    error!("Failed to update status for {}: {}", instance.name, e);
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
            Message::UpdateMetrics
        })
    }

    /// Builds the left panel containing configuration selection and new config button.
    ///
    /// # Returns
    /// Container element with the configuration list
    fn build_config_selection_panel(&self) -> Element<Message> {
        let config_buttons = self.build_config_button_list();
        let new_config_button = self.build_new_config_button();

        container(
            column![config_buttons, new_config_button]
                .height(Length::Fill)
                .clip(false),
        )
        .width(Length::FillPortion(1))
        .height(Length::Fill)
        .style(Self::container_style)
        .into()
    }

    /// Builds the scrollable list of configuration buttons.
    ///
    /// # Returns
    /// Scrollable element containing configuration buttons
    fn build_config_button_list(&self) -> Element<Message> {
        let mut configs = self.configs.keys().collect::<Vec<_>>();
        configs.sort();

        scrollable(column(
            configs
                .into_iter()
                .map(|name| self.build_config_button(name)),
        ))
        .height(Length::Fill)
        .into()
    }

    /// Builds a single configuration selection button.
    ///
    /// # Arguments
    /// * `name` - Name of the configuration
    ///
    /// # Returns
    /// Button element for the configuration
    fn build_config_button<'a>(&self, name: &'a str) -> Element<'a, Message> {
        let btn = button(text(name))
            .width(Length::Fill)
            .on_press(Message::ConfigSelected(name.to_string()));

        let is_selected = self
            .selected_config
            .as_ref()
            .is_some_and(|config| config.quincy_config.name == name);

        if is_selected {
            btn.style(primary)
        } else {
            btn.style(secondary)
        }
        .into()
    }

    /// Builds the "New Configuration" button.
    ///
    /// # Returns
    /// Button element for creating new configurations
    fn build_new_config_button(&self) -> Element<Message> {
        button(text("+").center().width(Length::Fill))
            .width(Length::Fill)
            .on_press(Message::NewConfig)
            .style(secondary)
            .into()
    }

    /// Builds the right panel containing configuration details and controls.
    ///
    /// # Returns
    /// Container element with configuration editing interface
    fn build_config_details_panel(&self) -> Element<Message> {
        let content = if let Some(selected_config) = self.selected_config.as_ref() {
            self.build_selected_config_content(selected_config)
        } else {
            self.build_no_selection_content()
        };

        container(content)
            .width(Length::FillPortion(3))
            .height(Length::Fill)
            .style(Self::container_style)
            .into()
    }

    /// Builds the content for when a configuration is selected.
    ///
    /// # Arguments
    /// * `selected_config` - The currently selected configuration
    ///
    /// # Returns
    /// Column element with configuration editing interface
    fn build_selected_config_content<'a>(
        &'a self,
        selected_config: &'a SelectedConfig,
    ) -> Element<'a, Message> {
        let has_client = self
            .instances
            .contains_key(&selected_config.quincy_config.name);

        let name_input = self.build_config_name_input(selected_config);
        let text_editor = self.build_config_text_editor(selected_config);
        let monitoring_section = self.build_monitoring_section(selected_config, has_client);
        let action_buttons = self.build_action_buttons(has_client);

        column![name_input, text_editor, monitoring_section, action_buttons]
            .spacing(10)
            .padding(20)
            .into()
    }

    /// Builds the configuration name input field.
    ///
    /// # Arguments
    /// * `selected_config` - The currently selected configuration
    ///
    /// # Returns
    /// Text input element for the configuration name
    fn build_config_name_input(&self, selected_config: &SelectedConfig) -> Element<Message> {
        text_input("Configuration name", &selected_config.quincy_config.name)
            .on_input(Message::ConfigNameChanged)
            .on_submit(Message::ConfigNameSaved)
            .into()
    }

    /// Builds the configuration text editor.
    ///
    /// # Arguments
    /// * `selected_config` - The currently selected configuration
    ///
    /// # Returns
    /// Text editor element for configuration content
    fn build_config_text_editor<'a>(
        &self,
        selected_config: &'a SelectedConfig,
    ) -> Element<'a, Message> {
        text_editor(&selected_config.editable_content)
            .on_action(Message::ConfigEdited)
            .highlight("toml", highlighter::Theme::InspiredGitHub)
            .height(Length::Fill)
            .into()
    }

    /// Builds the monitoring section showing connection status and metrics.
    ///
    /// # Arguments
    /// * `selected_config` - The currently selected configuration
    /// * `has_client` - Whether a client instance is running for this config
    ///
    /// # Returns
    /// Column element with monitoring information
    fn build_monitoring_section(
        &self,
        selected_config: &SelectedConfig,
        has_client: bool,
    ) -> Element<Message> {
        if has_client {
            if let Some(instance) = self.instances.get(&selected_config.quincy_config.name) {
                self.build_instance_status_display(instance.get_status())
            } else {
                // Show loading status when client is starting
                column![self.build_connection_status_section(&ConnectionStatus::Connecting)].into()
            }
        } else {
            // Always show disconnected status when no client is running
            column![self.build_connection_status_section(&ConnectionStatus::Disconnected)].into()
        }
    }

    /// Builds the status display for a running instance.
    ///
    /// # Arguments
    /// * `status` - Current client status and metrics
    ///
    /// # Returns
    /// Column element with status information
    fn build_instance_status_display(&self, status: &ClientStatus) -> Element<Message> {
        let connection_status_section = self.build_connection_status_section(&status.status);

        let mut sections = vec![connection_status_section];

        if let Some(ref metrics) = status.metrics {
            sections.push(self.build_metrics_section(metrics));
        }

        column(sections).spacing(15).into()
    }

    /// Builds the connection status section.
    ///
    /// # Arguments
    /// * `status` - Current connection status
    ///
    /// # Returns
    /// Container element with connection status information
    fn build_connection_status_section(&self, status: &ConnectionStatus) -> Element<Message> {
        container(
            column![
                text("Connection Status").size(16),
                text(format!("{:?}", status)).size(14)
            ]
            .spacing(5),
        )
        .style(Self::status_section_style)
        .padding(10)
        .width(Length::Fill)
        .into()
    }

    /// Builds the metrics section.
    ///
    /// # Arguments
    /// * `metrics` - Connection metrics to display
    ///
    /// # Returns
    /// Container element with transfer statistics
    fn build_metrics_section(&self, metrics: &ConnectionMetrics) -> Element<Message> {
        container(
            column![
                text("Connection Statistics").size(16),
                self.build_transfer_stats(metrics),
                self.build_connection_info(metrics)
            ]
            .spacing(8),
        )
        .style(Self::status_section_style)
        .padding(10)
        .width(Length::Fill)
        .into()
    }

    /// Builds the transfer statistics display.
    ///
    /// # Arguments
    /// * `metrics` - Connection metrics to display
    ///
    /// # Returns
    /// Row element with upload/download statistics
    fn build_transfer_stats(&self, metrics: &ConnectionMetrics) -> Element<Message> {
        row![
            column![
                text("Upload").size(12),
                text(format_bytes(metrics.bytes_sent)).size(14),
                text(format!("{} packets", metrics.packets_sent)).size(10)
            ]
            .spacing(2),
            column![
                text("Download").size(12),
                text(format_bytes(metrics.bytes_received)).size(14),
                text(format!("{} packets", metrics.packets_received)).size(10)
            ]
            .spacing(2)
        ]
        .spacing(40)
        .into()
    }

    /// Builds the connection information display.
    ///
    /// # Arguments
    /// * `metrics` - Connection metrics to display
    ///
    /// # Returns
    /// Text element with connection duration
    fn build_connection_info(&self, metrics: &ConnectionMetrics) -> Element<Message> {
        text(format!("Connected for: {:?}", metrics.connection_duration))
            .size(12)
            .into()
    }

    /// Builds the action buttons row (Connect/Disconnect, Save, Delete).
    ///
    /// # Arguments
    /// * `has_client` - Whether a client instance is running
    ///
    /// # Returns
    /// Row element with action buttons
    fn build_action_buttons(&self, has_client: bool) -> Element<Message> {
        let connection_button = if has_client {
            column![button(text("Disconnect"))
                .on_press(Message::Disconnect)
                .style(primary)]
            .align_x(Horizontal::Left)
        } else {
            column![button(text("Connect"))
                .on_press(Message::Connect)
                .style(primary)]
            .align_x(Horizontal::Left)
        };

        let save_button = column![button(text("Save"))
            .on_press(Message::ConfigSave)
            .style(secondary)]
        .align_x(Horizontal::Right);

        let delete_button = if has_client {
            // Disable delete button when client is running
            column![button(text("Delete")).style(danger)].align_x(Horizontal::Right)
        } else {
            column![button(text("Delete"))
                .on_press(Message::ConfigDelete)
                .style(danger)]
            .align_x(Horizontal::Right)
        };

        row![connection_button, save_button, delete_button]
            .width(Length::Fill)
            .into()
    }

    /// Builds the content shown when no configuration is selected.
    ///
    /// # Returns
    /// Column element with "no selection" message
    fn build_no_selection_content(&self) -> Element<Message> {
        column![text("No configuration selected")
            .size(24)
            .align_x(Horizontal::Center)
            .width(Length::Fill)]
        .spacing(10)
        .padding(20)
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Horizontal::Center)
        .into()
    }

    /// Creates the container style for panels.
    ///
    /// # Arguments
    /// * `theme` - Current application theme
    ///
    /// # Returns
    /// Style configuration for container elements
    fn container_style(theme: &Theme) -> Style {
        let palette = theme.extended_palette();

        Style {
            background: Some(palette.background.weak.color.into()),
            border: border::rounded(3),
            ..Style::default()
        }
    }

    /// Creates the style for status section containers.
    ///
    /// # Arguments
    /// * `theme` - Current application theme
    ///
    /// # Returns
    /// Style configuration for status section elements
    fn status_section_style(theme: &Theme) -> Style {
        let palette = theme.extended_palette();

        Style {
            background: Some(palette.background.strong.color.into()),
            border: border::rounded(5),
            ..Style::default()
        }
    }
}

/// Formats byte counts into human-readable strings with appropriate units.
///
/// This function converts byte counts into readable format using binary units
/// (1024-based) with one decimal place precision.
///
/// # Arguments
/// * `bytes` - Number of bytes to format
///
/// # Returns
/// Formatted string with value and unit (e.g., "1.5 MB")
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

/// Expands environment variables and home directory shortcuts in file paths.
///
/// This function handles platform-specific path expansion:
/// - On Unix: Expands `~/` to the user's home directory
/// - On Windows: Expands `%AppData%` to the application data directory
///
/// # Arguments
/// * `path` - Path that may contain environment variables or shortcuts
///
/// # Returns
/// Expanded path with environment variables resolved
pub fn expand_path(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();

    #[cfg(unix)]
    if path_str.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(path_str.replacen("~", &home, 1));
        }
    }

    #[cfg(windows)]
    if path_str.contains("%AppData%") {
        if let Ok(app_data) = std::env::var("APPDATA") {
            return PathBuf::from(path_str.replace("%AppData%", &app_data));
        }
    }

    path.to_path_buf()
}
