use iced::widget::text_editor;
use iced::Task;
use quincy::config::{ClientConfig, FromPath};
use quincy::Result;
use std::fs;
use std::path::Path;
use std::process;
use std::time::Instant;
use tracing::{debug, error, info, warn};

use super::app::QuincyGui;
use super::error::GuiError;
use super::types::{
    ConfigState, ConfirmAction, ConfirmMsg, ConfirmationState, EditorState, InstanceMsg, Message,
    QuincyConfig, QuincyInstance, SelectedConfig, SystemMsg,
};
use crate::ipc::{ConnectionMetrics, ConnectionStatus, IpcMessage};
use crate::validation;

/// Helper function to parse a config file and return the parsed config and any error.
/// Returns a tuple of (Option<ClientConfig>, Option<String>) where:
/// - The first element is Some(config) if parsing succeeded, None otherwise
/// - The second element is Some(error_string) if parsing failed, None otherwise
fn try_parse_config(path: &Path, name: &str) -> (Option<ClientConfig>, Option<String>) {
    match ClientConfig::from_path(path, "QUINCY_") {
        Ok(cfg) => (Some(cfg), None),
        Err(e) => {
            warn!("Failed to parse config {}: {}", name, e);
            (None, Some(e.to_string()))
        }
    }
}

impl QuincyGui {
    // ========== Configuration Selection Handlers ==========

    /// Handles selection of a configuration from the list.
    pub fn handle_config_selected(&mut self, name: String) -> Task<Message> {
        // Don't allow selection changes while editor is open
        if self.editor_state.is_some() {
            return Task::none();
        }

        // Don't allow selection changes while any config is in an active state
        // (Connecting, Connected, or Disconnecting) to avoid confusion about which config is running
        if self
            .config_states
            .values()
            .any(|state| state.has_active_instance())
        {
            return Task::none();
        }

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
    pub fn load_config_content(&self, config: &QuincyConfig) -> Result<SelectedConfig> {
        let config_content = fs::read_to_string(&config.path)?;
        let editable_content = text_editor::Content::with_text(&config_content);

        let (parsed_config, parse_error) = try_parse_config(&config.path, &config.name);

        Ok(SelectedConfig {
            quincy_config: config.clone(),
            editable_content,
            parsed_config,
            parse_error,
        })
    }

    // ========== Configuration Editing Handlers ==========

    /// Handles changes to the configuration name.
    pub fn handle_config_name_changed(&mut self, new_name: String) -> Task<Message> {
        if self.editor_state.is_some() {
            return Task::none();
        }

        if let Some(selected_config) = self.selected_config.as_mut() {
            selected_config.quincy_config.name = new_name;
        } else {
            error!("No configuration selected");
        }
        Task::none()
    }

    /// Handles saving of a renamed configuration.
    pub fn handle_config_name_saved(&mut self) -> Task<Message> {
        if self.editor_state.is_some() {
            return Task::none();
        }

        let old_config_name = {
            let Some(ref selected_config) = self.selected_config else {
                error!("No configuration selected");
                return Task::none();
            };

            // Extract old config name from file path
            let file_name = match selected_config.quincy_config.path.file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => return Task::none(),
            };

            file_name
                .to_lowercase()
                .strip_suffix(".toml")
                .unwrap_or(&file_name)
                .to_string()
        };

        let Some(mut selected_config) = self.selected_config.take() else {
            return Task::none();
        };

        // Validate the new name
        if let Err(e) = validation::validate_config_name(&selected_config.quincy_config.name) {
            self.config_states.insert(
                selected_config.quincy_config.name.clone(),
                ConfigState::Error { error: e.into() },
            );
            self.selected_config = Some(selected_config);
            return Task::none();
        }

        self.rename_config_file(&mut selected_config, &old_config_name);
        self.selected_config = Some(selected_config);
        Task::none()
    }

    /// Renames a configuration file and updates internal state.
    pub fn rename_config_file(
        &mut self,
        selected_config: &mut SelectedConfig,
        old_config_name: &str,
    ) {
        self.configs.remove(old_config_name);
        let old_state = self
            .config_states
            .remove(old_config_name)
            .unwrap_or_default();

        let old_path = selected_config.quincy_config.path.clone();
        let new_path = self
            .config_dir
            .join(format!("{}.toml", selected_config.quincy_config.name));

        self.save_config_to_new_path(selected_config, &new_path);

        // Remove old config file
        match fs::remove_file(&old_path) {
            Ok(_) => info!("Old config file removed: {}", old_path.display()),
            Err(e) => error!("Failed to remove old config file: {}", e),
        }

        let new_name = selected_config.quincy_config.name.clone();
        self.configs
            .insert(new_name.clone(), selected_config.quincy_config.clone());
        self.config_states.insert(new_name, old_state);
    }

    /// Saves configuration content to a new file path.
    pub fn save_config_to_new_path(
        &mut self,
        selected_config: &mut SelectedConfig,
        new_path: &Path,
    ) {
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

    /// Handles deletion of the current configuration.
    /// Shows a confirmation modal instead of deleting immediately.
    pub fn handle_config_delete(&mut self) -> Task<Message> {
        if self.editor_state.is_some() || self.confirmation_state.is_some() {
            return Task::none();
        }

        let selected_config = match self.selected_config.as_ref() {
            Some(config) => config,
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        let config_name = selected_config.quincy_config.name.clone();

        let confirmation_state = ConfirmationState {
            title: "Delete Configuration".to_string(),
            message: format!("Are you sure you want to delete '{}'?", config_name),
            confirm_action: ConfirmAction::DeleteConfig(config_name),
        };

        Task::done(Message::Confirm(ConfirmMsg::Show(confirmation_state)))
    }

    /// Handles creation of a new configuration.
    pub fn handle_new_config(&mut self) -> Task<Message> {
        if self.editor_state.is_some() {
            return Task::none();
        }

        // Generate unique config name
        let mut config_idx = 0;
        let mut new_config_name = "client_config".to_string();
        while self.configs.contains_key(&new_config_name) {
            config_idx += 1;
            new_config_name = format!("client_config_{config_idx}");
        }

        // Create new config
        let new_config = QuincyConfig {
            name: new_config_name.clone(),
            path: self.config_dir.join(format!("{}.toml", new_config_name)),
        };

        // Create selected config with template
        let selected_config = SelectedConfig {
            quincy_config: new_config.clone(),
            editable_content: text_editor::Content::with_text(include_str!(
                "../../../resources/common/client.toml"
            )),
            parsed_config: None,
            parse_error: None,
        };

        // Save to disk
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

        self.selected_config = Some(selected_config);
        self.configs.insert(new_config_name.clone(), new_config);
        self.config_states
            .insert(new_config_name, ConfigState::default());

        Task::none()
    }

    // ========== Editor Modal Handlers ==========

    /// Opens the editor modal with the current configuration content.
    pub fn handle_open_editor(&mut self) -> Task<Message> {
        let selected_config = match self.selected_config.as_ref() {
            Some(config) => config,
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        let config_name = selected_config.quincy_config.name.clone();
        let config_content = selected_config.editable_content.text();

        self.editor_state = Some(EditorState {
            config_name: config_name.clone(),
            content: text_editor::Content::with_text(&config_content),
        });

        info!("Editor opened for config: {}", config_name);
        Task::none()
    }

    /// Handles text editor actions in the modal.
    pub fn handle_editor_action(&mut self, action: text_editor::Action) -> Task<Message> {
        if let Some(editor_state) = self.editor_state.as_mut() {
            editor_state.content.perform(action);
            debug!("Editor action applied");
        }
        Task::none()
    }

    /// Closes the editor modal without saving.
    pub fn handle_close_editor(&mut self) -> Task<Message> {
        let editor_state = match self.editor_state.as_ref() {
            Some(state) => state,
            None => return Task::none(),
        };

        // Get the original content from selected_config
        let original_content = match self.selected_config.as_ref() {
            Some(config) => config.editable_content.text(),
            None => {
                error!("No configuration selected");
                self.editor_state = None;
                return Task::none();
            }
        };

        let current_content = editor_state.content.text();

        // Check if there are unsaved changes
        if original_content != current_content {
            // Show confirmation dialog
            let confirmation_state = ConfirmationState {
                title: "Unsaved Changes".to_string(),
                message: "You have unsaved changes. Are you sure you want to discard them?"
                    .to_string(),
                confirm_action: ConfirmAction::DiscardEditorChanges,
            };
            return Task::done(Message::Confirm(ConfirmMsg::Show(confirmation_state)));
        }

        // No changes, close immediately
        if let Some(editor_state) = self.editor_state.take() {
            info!(
                "Editor closed without changes for config: {}",
                editor_state.config_name
            );
        }
        Task::none()
    }

    /// Saves changes from the editor and closes the modal.
    pub fn handle_save_editor(&mut self) -> Task<Message> {
        let editor_state = match self.editor_state.take() {
            Some(state) => state,
            None => {
                error!("No editor state to save");
                return Task::none();
            }
        };

        let selected_config = match self.selected_config.as_mut() {
            Some(config) => config,
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        let config_content = editor_state.content.text();

        // Update the selected config's editable content
        selected_config.editable_content = text_editor::Content::with_text(&config_content);

        // Save to disk
        match fs::write(&selected_config.quincy_config.path, &config_content) {
            Ok(_) => {
                info!(
                    "Config file saved: {}",
                    selected_config.quincy_config.path.display()
                );

                // Re-parse the configuration
                let (parsed_config, parse_error) = try_parse_config(
                    &selected_config.quincy_config.path,
                    &selected_config.quincy_config.name,
                );
                selected_config.parsed_config = parsed_config;
                selected_config.parse_error = parse_error;

                // Update configs map
                self.configs.insert(
                    selected_config.quincy_config.name.clone(),
                    selected_config.quincy_config.clone(),
                );
            }
            Err(e) => {
                error!("Failed to save config file: {}", e);
            }
        }

        Task::none()
    }

    // ========== Connection State Machine Handlers ==========

    /// Handles VPN connection request.
    /// Transitions: Idle/Error -> Connecting
    pub fn handle_connect(&mut self) -> Task<Message> {
        if self.editor_state.is_some() {
            return Task::none();
        }

        let (config_name, config_path) = match self.selected_config.as_ref() {
            Some(config) => (
                config.quincy_config.name.clone(),
                config.quincy_config.path.clone(),
            ),
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        let current_state = self
            .config_states
            .get(&config_name)
            .cloned()
            .unwrap_or_default();

        if current_state.has_active_instance() {
            warn!(
                "Config {config_name} is already connecting/connected; ignoring duplicate request"
            );
            return Task::none();
        }

        if let Err(e) = validation::validate_config_name(&config_name) {
            self.config_states
                .insert(config_name, ConfigState::Error { error: e.into() });
            return Task::none();
        }

        // Set state to Connecting immediately (instance will be set when IPC connects)
        self.config_states.insert(
            config_name.clone(),
            ConfigState::Connecting {
                started_at: Instant::now(),
                instance: None,
            },
        );

        Task::future(async move {
            info!("Connecting to instance: {}", config_name);

            match QuincyInstance::start(config_name.clone(), config_path).await {
                Ok((instance, metrics)) => {
                    info!(
                        "Instance {} started, waiting for VPN connection",
                        config_name
                    );
                    Message::Instance(InstanceMsg::ConnectedInstance(instance, metrics))
                }
                Err(e) => {
                    error!("Failed to start Quincy instance: {}", e);
                    Message::Instance(InstanceMsg::ConnectFailed(config_name, e.into()))
                }
            }
        })
    }

    /// Handles VPN disconnection request.
    /// Transitions: Connected -> Disconnecting -> Idle
    pub fn handle_disconnect(&mut self) -> Task<Message> {
        if self.editor_state.is_some() {
            return Task::none();
        }

        let config_name = match &self.selected_config {
            Some(config) => config.quincy_config.name.clone(),
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        let current_state = self.config_states.remove(&config_name);
        let mut instance = match current_state {
            Some(ConfigState::Connected { instance, .. }) => instance,
            Some(other) => {
                self.config_states.insert(config_name.clone(), other);
                error!("Cannot disconnect: not in Connected state");
                return Task::none();
            }
            None => {
                error!("No state found for configuration: {}", config_name);
                return Task::none();
            }
        };

        self.config_states
            .insert(config_name.clone(), ConfigState::Disconnecting);

        info!("Disconnecting instance: {}", config_name);

        Task::future(async move {
            match instance.stop().await {
                Ok(_) => info!("Instance {} disconnected", config_name),
                Err(e) => error!("Failed to stop client instance: {}", e),
            }

            Message::Instance(InstanceMsg::Disconnected)
        })
    }

    /// Handles cancellation of an in-progress connection.
    /// Transitions: Connecting -> Idle
    pub fn handle_cancel_connect(&mut self) -> Task<Message> {
        let config_name = match &self.selected_config {
            Some(config) => config.quincy_config.name.clone(),
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        // Get the current state and extract instance if in Connecting state
        let current_state = self.config_states.remove(&config_name);
        match current_state {
            Some(ConfigState::Connecting { instance, .. }) => {
                info!("Cancelling connection for: {}", config_name);

                // Transition to Idle immediately
                self.config_states
                    .insert(config_name.clone(), ConfigState::Idle);

                // Send shutdown to daemon via IPC if we have an instance
                if let Some(inst) = instance {
                    Task::future(async move {
                        if let Some(ipc_client) = inst.ipc_client() {
                            let mut conn = ipc_client.lock().await;
                            if let Err(e) = conn.send(&IpcMessage::Shutdown).await {
                                warn!("Failed to send shutdown to daemon: {}", e);
                            } else {
                                info!("Sent shutdown to daemon for {}", config_name);
                            }
                        }
                        Message::Instance(InstanceMsg::Disconnected)
                    })
                } else {
                    // No instance yet (still spawning daemon), just transition to Idle
                    // The async task will return ConnectFailed or ConnectedInstance,
                    // which we'll ignore since we're now Idle
                    info!("Cancelled before daemon connected for {}", config_name);
                    Task::none()
                }
            }
            Some(other) => {
                // Not in Connecting state, put it back
                self.config_states.insert(config_name, other);
                warn!("Cannot cancel: not in Connecting state");
                Task::none()
            }
            None => {
                warn!("Cannot cancel: no state found");
                Task::none()
            }
        }
    }

    /// Handles periodic metrics updates for all connected and connecting instances.
    /// Also polls instances in `Connecting` state to detect when they become `Connected`.
    pub fn handle_update_metrics(&self) -> Task<Message> {
        let tasks: Vec<Task<Message>> = self
            .config_states
            .iter()
            .filter_map(|(name, state)| {
                let instance = match state {
                    ConfigState::Connected { instance, .. } => instance,
                    ConfigState::Connecting {
                        instance: Some(instance),
                        ..
                    } => instance,
                    _ => return None,
                };
                let name = name.clone();
                let ipc_client = instance.ipc_client()?.clone();
                Some((name, ipc_client))
            })
            .map(|(name, ipc_client)| {
                Task::future(async move {
                    let mut conn = ipc_client.lock().await;
                    if let Err(e) = conn.send(&IpcMessage::GetStatus).await {
                        return Message::Instance(InstanceMsg::DisconnectedWithError(
                            name,
                            GuiError::ipc(e.to_string()),
                        ));
                    }
                    match conn.recv().await {
                        Ok(IpcMessage::StatusUpdate(status)) => match status.status {
                            ConnectionStatus::Disconnected => {
                                Message::Instance(InstanceMsg::DisconnectedWithError(
                                    name,
                                    GuiError::connection_closed("Connection lost"),
                                ))
                            }
                            ConnectionStatus::Error(err) => {
                                Message::Instance(InstanceMsg::DisconnectedWithError(name, err))
                            }
                            ConnectionStatus::Connecting => {
                                // Still connecting, no state change needed
                                Message::System(SystemMsg::Noop)
                            }
                            ConnectionStatus::Connected => {
                                Message::Instance(InstanceMsg::StatusUpdated(name, status.metrics))
                            }
                        },
                        Ok(IpcMessage::Error(err)) => {
                            Message::Instance(InstanceMsg::DisconnectedWithError(name, err))
                        }
                        Ok(other) => Message::Instance(InstanceMsg::DisconnectedWithError(
                            name,
                            GuiError::ipc(format!("Unexpected IPC message: {:?}", other)),
                        )),
                        Err(e) => Message::Instance(InstanceMsg::DisconnectedWithError(
                            name,
                            GuiError::ipc(e.to_string()),
                        )),
                    }
                })
            })
            .collect();

        Task::batch(tasks)
    }

    /// Handles disconnection with error.
    /// Transitions: Any -> Error
    pub fn handle_disconnected_with_error(
        &mut self,
        name: String,
        error: GuiError,
    ) -> Task<Message> {
        info!("Config {} disconnected with error: {}", name, error);
        self.config_states
            .insert(name, ConfigState::Error { error });
        Task::none()
    }

    /// Handles successful instance startup (daemon connected, VPN connecting).
    /// Transitions: Idle -> Connecting
    /// The daemon is now connected via IPC and starting the VPN connection.
    pub fn handle_connected_instance(
        &mut self,
        instance: QuincyInstance,
        metrics: Option<ConnectionMetrics>,
    ) -> Task<Message> {
        let name = instance.name.clone();

        // If we have metrics, go straight to Connected
        // Otherwise, update Connecting state with the instance
        if metrics.is_some() {
            info!("Instance {} fully connected", name);
            self.config_states
                .insert(name, ConfigState::Connected { instance, metrics });
        } else {
            info!("Instance {} daemon started, VPN connecting", name);
            // Preserve the original started_at if we're already in Connecting state
            let started_at = match self.config_states.get(&name) {
                Some(ConfigState::Connecting { started_at, .. }) => *started_at,
                _ => Instant::now(),
            };
            self.config_states.insert(
                name,
                ConfigState::Connecting {
                    started_at,
                    instance: Some(instance),
                },
            );
        }

        Task::none()
    }

    /// Handles status/metrics update from daemon.
    /// May transition Connecting -> Connected when VPN is ready.
    pub fn handle_status_updated(
        &mut self,
        name: String,
        metrics: Option<ConnectionMetrics>,
    ) -> Task<Message> {
        let current_state = self.config_states.remove(&name);

        match current_state {
            Some(ConfigState::Connecting {
                instance: Some(instance),
                ..
            }) => {
                // VPN is now connected
                info!("Instance {} VPN connected", name);
                self.config_states
                    .insert(name, ConfigState::Connected { instance, metrics });
            }
            Some(ConfigState::Connecting { instance: None, .. }) => {
                // No instance yet, can't transition - put state back
                warn!("Status update for {} but no instance yet", name);
                self.config_states.insert(
                    name,
                    ConfigState::Connecting {
                        started_at: Instant::now(),
                        instance: None,
                    },
                );
            }
            Some(ConfigState::Connected { instance, .. }) => {
                // Update metrics
                self.config_states
                    .insert(name, ConfigState::Connected { instance, metrics });
            }
            Some(other) => {
                // Put it back unchanged
                self.config_states.insert(name, other);
            }
            None => {}
        }

        Task::none()
    }

    /// Handles successful disconnection.
    /// Transitions: Disconnecting -> Idle
    pub fn handle_disconnected(&mut self) -> Task<Message> {
        let config_name = match &self.selected_config {
            Some(config) => config.quincy_config.name.clone(),
            None => {
                error!("No configuration selected");
                return Task::none();
            }
        };

        let current_state = self.config_states.get(&config_name);
        if !matches!(current_state, Some(ConfigState::Disconnecting)) {
            debug!(
                "Ignoring Disconnected message for {} in state {:?}",
                config_name, current_state
            );
            return Task::none();
        }

        info!("Instance {} disconnected successfully", config_name);
        self.config_states.insert(config_name, ConfigState::Idle);
        Task::none()
    }

    /// Handles a successful connection event (legacy handler).
    pub fn handle_connected(&mut self, _config_name: String) -> Task<Message> {
        Task::none()
    }

    /// Handles a failed connection attempt.
    /// Transitions: Connecting -> Error
    pub fn handle_connect_failed(&mut self, config_name: String, error: GuiError) -> Task<Message> {
        info!("Connection failed for {}: {}", config_name, error);
        self.config_states
            .insert(config_name, ConfigState::Error { error });
        Task::none()
    }

    // ========== Window Lifecycle Handlers ==========

    /// Handles window closed event - shuts down all connections and exits.
    pub fn handle_window_closed(&mut self, _window_id: iced::window::Id) -> Task<Message> {
        info!("Window closed, shutting down application");

        let shutdown_tasks: Vec<Task<Message>> = self
            .config_states
            .iter_mut()
            .filter_map(|(name, state)| {
                if let ConfigState::Connected { instance, .. } = state {
                    let name = name.clone();
                    let mut instance = instance.clone();
                    Some(Task::future(async move {
                        if let Err(e) = instance.stop().await {
                            error!("Failed to stop instance {}: {}", name, e);
                        }
                        Message::Instance(InstanceMsg::Disconnected)
                    }))
                } else {
                    None
                }
            })
            .collect();

        for state in self.config_states.values_mut() {
            *state = ConfigState::Idle;
        }

        Task::batch(shutdown_tasks).chain(Task::future(exit()))
    }

    // ========== Confirmation Modal Handlers ==========

    /// Shows a confirmation modal with the given state.
    pub fn handle_show_confirmation(&mut self, state: ConfirmationState) -> Task<Message> {
        info!(
            "Showing confirmation modal: {} - {}",
            state.title, state.message
        );
        self.confirmation_state = Some(state);
        Task::none()
    }

    /// Handles confirmation action (user clicked Confirm).
    pub fn handle_confirm(&mut self) -> Task<Message> {
        let confirmation_state = match self.confirmation_state.take() {
            Some(state) => state,
            None => {
                error!("No confirmation state to confirm");
                return Task::none();
            }
        };

        match confirmation_state.confirm_action {
            ConfirmAction::DeleteConfig(config_name) => self.perform_delete_config(config_name),
            ConfirmAction::DiscardEditorChanges => {
                // Close the editor and discard changes
                if let Some(editor_state) = self.editor_state.take() {
                    info!(
                        "Editor closed, changes discarded for config: {}",
                        editor_state.config_name
                    );
                }
                Task::none()
            }
        }
    }

    /// Handles cancel action (user clicked Cancel).
    pub fn handle_cancel_confirmation(&mut self) -> Task<Message> {
        if let Some(confirmation_state) = self.confirmation_state.take() {
            info!(
                "Confirmation cancelled: {} - {}",
                confirmation_state.title, confirmation_state.message
            );
        }
        Task::none()
    }

    /// Performs the actual deletion of a configuration.
    fn perform_delete_config(&mut self, config_name: String) -> Task<Message> {
        let config = match self.configs.get(&config_name) {
            Some(config) => config.clone(),
            None => {
                error!("Configuration not found: {}", config_name);
                return Task::none();
            }
        };

        match fs::remove_file(&config.path) {
            Ok(_) => {
                info!("Config file deleted: {}", config.path.display());
            }
            Err(e) => {
                error!("Failed to delete config file: {}", e);
            }
        }

        self.configs.remove(&config_name);
        self.config_states.remove(&config_name);

        // If this was the selected config, clear the selection
        if let Some(selected) = &self.selected_config {
            if selected.quincy_config.name == config_name {
                self.selected_config = None;
            }
        }

        Task::none()
    }
}

/// Exits the application gracefully.
async fn exit() -> Message {
    process::exit(0);
}
