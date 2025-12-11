use iced::widget::text_editor;
use iced::Task;
use quincy::config::{ClientConfig, FromPath};
use std::fs;
use std::path::Path;
use std::process;
use std::time::Instant;
use tracing::{debug, error, info, warn};

use super::app::QuincyGui;
use super::error::GuiError;
use super::types::{
    ConfigEntry, ConfigState, ConfirmAction, ConfirmMsg, ConfirmationState, EditorState,
    InstanceMsg, Message, QuincyConfig, QuincyInstance, SystemMsg,
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
            .configs
            .values()
            .any(|entry| entry.state.has_active_instance())
        {
            return Task::none();
        }

        let Some(entry) = self.configs.get_mut(&name) else {
            error!("Configuration not found: {name}");
            return Task::none();
        };

        // Parse the config if not already parsed
        if entry.parsed.is_none() && entry.parse_error.is_none() {
            let (parsed, parse_error) = try_parse_config(&entry.config.path, &entry.config.name);
            entry.parsed = parsed;
            entry.parse_error = parse_error;
        }

        self.selected_config = Some(name.clone());
        info!("Config selected: {name}");
        Task::none()
    }

    // ========== Configuration Editing Handlers ==========

    /// Handles changes to the configuration name.
    /// Note: This updates the name in-place; the actual rename happens on NameSaved.
    pub fn handle_config_name_changed(&mut self, new_name: String) -> Task<Message> {
        if self.editor_state.is_some() {
            return Task::none();
        }

        let Some(ref selected_key) = self.selected_config else {
            error!("No configuration selected");
            return Task::none();
        };

        if let Some(entry) = self.configs.get_mut(selected_key) {
            entry.config.name = new_name;
        }
        Task::none()
    }

    /// Handles saving of a renamed configuration.
    pub fn handle_config_name_saved(&mut self) -> Task<Message> {
        if self.editor_state.is_some() {
            return Task::none();
        }

        let Some(old_key) = self.selected_config.take() else {
            error!("No configuration selected");
            return Task::none();
        };

        let Some(mut entry) = self.configs.remove(&old_key) else {
            error!("Configuration not found: {}", old_key);
            return Task::none();
        };

        let new_name = entry.config.name.clone();

        // If name hasn't changed, just put it back
        if new_name == old_key {
            self.configs.insert(old_key.clone(), entry);
            self.selected_config = Some(old_key);
            return Task::none();
        }

        // Validate the new name
        if let Err(e) = validation::validate_config_name(&new_name) {
            entry.state = ConfigState::Error { error: e.into() };
            self.configs.insert(old_key.clone(), entry);
            self.selected_config = Some(old_key);
            return Task::none();
        }

        // Perform the file rename
        let old_path = entry.config.path.clone();
        let new_path = self.config_dir.join(format!("{}.toml", new_name));

        // Read current content and write to new path
        match fs::read_to_string(&old_path) {
            Ok(content) => {
                if let Err(e) = fs::write(&new_path, &content) {
                    error!("Failed to save config file: {}", e);
                    self.configs.insert(old_key.clone(), entry);
                    self.selected_config = Some(old_key);
                    return Task::none();
                }
                info!("Config file saved: {}", new_path.display());
            }
            Err(e) => {
                error!("Failed to read config file: {}", e);
                self.configs.insert(old_key.clone(), entry);
                self.selected_config = Some(old_key);
                return Task::none();
            }
        }

        // Remove old config file
        match fs::remove_file(&old_path) {
            Ok(_) => info!("Old config file removed: {}", old_path.display()),
            Err(e) => error!("Failed to remove old config file: {}", e),
        }

        // Update the entry with new path
        entry.config.path = new_path;

        // Insert under new key
        self.configs.insert(new_name.clone(), entry);
        self.selected_config = Some(new_name);
        Task::none()
    }

    /// Handles deletion of the current configuration.
    /// Shows a confirmation modal instead of deleting immediately.
    pub fn handle_config_delete(&mut self) -> Task<Message> {
        if self.editor_state.is_some() || self.confirmation_state.is_some() {
            return Task::none();
        }

        let Some(ref config_name) = self.selected_config else {
            error!("No configuration selected");
            return Task::none();
        };

        let confirmation_state = ConfirmationState {
            title: "Delete Configuration".to_string(),
            message: format!("Are you sure you want to delete '{}'?", config_name),
            confirm_action: ConfirmAction::DeleteConfig(config_name.clone()),
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

        let template_content = include_str!("../../resources/client.toml");
        let config_path = self.config_dir.join(format!("{}.toml", new_config_name));

        // Save to disk
        match fs::write(&config_path, template_content) {
            Ok(_) => {
                info!("Config file saved: {}", config_path.display());
            }
            Err(e) => {
                error!("Failed to save config file: {}", e);
                return Task::none();
            }
        }

        // Create new config entry
        let config = QuincyConfig {
            name: new_config_name.clone(),
            path: config_path,
        };

        let entry = ConfigEntry {
            config,
            state: ConfigState::default(),
            parsed: None,
            parse_error: None,
        };

        self.configs.insert(new_config_name.clone(), entry);
        self.selected_config = Some(new_config_name);

        Task::none()
    }

    // ========== Editor Modal Handlers ==========

    /// Opens the editor modal with the current configuration content.
    /// Reads the file fresh from disk to create the editor buffer.
    pub fn handle_open_editor(&mut self) -> Task<Message> {
        let Some(ref config_name) = self.selected_config else {
            error!("No configuration selected");
            return Task::none();
        };

        let Some(entry) = self.configs.get(config_name) else {
            error!("Configuration not found: {}", config_name);
            return Task::none();
        };

        // Read file content fresh from disk
        let config_content = match fs::read_to_string(&entry.config.path) {
            Ok(content) => content,
            Err(e) => {
                error!("Failed to read config file: {}", e);
                return Task::none();
            }
        };

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

        let Some(ref config_name) = self.selected_config else {
            error!("No configuration selected");
            self.editor_state = None;
            return Task::none();
        };

        let Some(entry) = self.configs.get(config_name) else {
            error!("Configuration not found: {}", config_name);
            self.editor_state = None;
            return Task::none();
        };

        // Read original content from disk to compare
        let original_content = match fs::read_to_string(&entry.config.path) {
            Ok(content) => content,
            Err(e) => {
                error!("Failed to read config file: {}", e);
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

        let Some(ref config_name) = self.selected_config else {
            error!("No configuration selected");
            return Task::none();
        };

        let Some(entry) = self.configs.get_mut(config_name) else {
            error!("Configuration not found: {}", config_name);
            return Task::none();
        };

        let config_content = editor_state.content.text();

        // Save to disk
        match fs::write(&entry.config.path, &config_content) {
            Ok(_) => {
                info!("Config file saved: {}", entry.config.path.display());

                // Re-parse the configuration
                let (parsed, parse_error) =
                    try_parse_config(&entry.config.path, &entry.config.name);
                entry.parsed = parsed;
                entry.parse_error = parse_error;
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

        let Some(ref config_name) = self.selected_config else {
            error!("No configuration selected");
            return Task::none();
        };

        let Some(entry) = self.configs.get_mut(config_name) else {
            error!("Configuration not found: {}", config_name);
            return Task::none();
        };

        if entry.state.has_active_instance() {
            warn!(
                "Config {} is already connecting/connected; ignoring duplicate request",
                config_name
            );
            return Task::none();
        }

        if let Err(e) = validation::validate_config_name(config_name) {
            entry.state = ConfigState::Error { error: e.into() };
            return Task::none();
        }

        let config_name = config_name.clone();
        let config_path = entry.config.path.clone();

        // Set state to Connecting immediately (instance will be set when IPC connects)
        entry.state = ConfigState::Connecting {
            started_at: Instant::now(),
            instance: None,
        };

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

        let Some(ref config_name) = self.selected_config else {
            error!("No configuration selected");
            return Task::none();
        };

        let Some(entry) = self.configs.get_mut(config_name) else {
            error!("Configuration not found: {}", config_name);
            return Task::none();
        };

        let mut instance = match std::mem::take(&mut entry.state) {
            ConfigState::Connected { instance, .. } => instance,
            other => {
                entry.state = other;
                error!("Cannot disconnect: not in Connected state");
                return Task::none();
            }
        };

        entry.state = ConfigState::Disconnecting;
        let config_name = config_name.clone();

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
        let Some(ref config_name) = self.selected_config else {
            error!("No configuration selected");
            return Task::none();
        };

        let Some(entry) = self.configs.get_mut(config_name) else {
            error!("Configuration not found: {}", config_name);
            return Task::none();
        };

        // Get the current state and extract instance if in Connecting state
        match std::mem::take(&mut entry.state) {
            ConfigState::Connecting { instance, .. } => {
                info!("Cancelling connection for: {}", config_name);

                // Transition to Idle immediately
                entry.state = ConfigState::Idle;

                let config_name = config_name.clone();

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
            other => {
                // Not in Connecting state, put it back
                entry.state = other;
                warn!("Cannot cancel: not in Connecting state");
                Task::none()
            }
        }
    }

    /// Handles periodic metrics updates for all connected and connecting instances.
    /// Also polls instances in `Connecting` state to detect when they become `Connected`.
    pub fn handle_update_metrics(&self) -> Task<Message> {
        let tasks: Vec<Task<Message>> = self
            .configs
            .iter()
            .filter_map(|(name, entry)| {
                let instance = match &entry.state {
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
        if let Some(entry) = self.configs.get_mut(&name) {
            entry.state = ConfigState::Error { error };
        }
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

        let Some(entry) = self.configs.get_mut(&name) else {
            warn!("Config {} not found for connected instance", name);
            return Task::none();
        };

        // If we have metrics, go straight to Connected
        // Otherwise, update Connecting state with the instance
        if metrics.is_some() {
            info!("Instance {} fully connected", name);
            entry.state = ConfigState::Connected { instance, metrics };
        } else {
            info!("Instance {} daemon started, VPN connecting", name);
            // Preserve the original started_at if we're already in Connecting state
            let started_at = match &entry.state {
                ConfigState::Connecting { started_at, .. } => *started_at,
                _ => Instant::now(),
            };
            entry.state = ConfigState::Connecting {
                started_at,
                instance: Some(instance),
            };
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
        let Some(entry) = self.configs.get_mut(&name) else {
            return Task::none();
        };

        match std::mem::take(&mut entry.state) {
            ConfigState::Connecting {
                instance: Some(instance),
                ..
            } => {
                // VPN is now connected
                info!("Instance {} VPN connected", name);
                entry.state = ConfigState::Connected { instance, metrics };
            }
            ConfigState::Connecting { instance: None, .. } => {
                // No instance yet, can't transition - put state back
                warn!("Status update for {} but no instance yet", name);
                entry.state = ConfigState::Connecting {
                    started_at: Instant::now(),
                    instance: None,
                };
            }
            ConfigState::Connected { instance, .. } => {
                // Update metrics
                entry.state = ConfigState::Connected { instance, metrics };
            }
            other => {
                // Put it back unchanged
                entry.state = other;
            }
        }

        Task::none()
    }

    /// Handles successful disconnection.
    /// Transitions: Disconnecting -> Idle
    pub fn handle_disconnected(&mut self) -> Task<Message> {
        let Some(ref config_name) = self.selected_config else {
            error!("No configuration selected");
            return Task::none();
        };

        let Some(entry) = self.configs.get_mut(config_name) else {
            error!("Configuration not found: {}", config_name);
            return Task::none();
        };

        if !matches!(entry.state, ConfigState::Disconnecting) {
            debug!(
                "Ignoring Disconnected message for {} in state {:?}",
                config_name, entry.state
            );
            return Task::none();
        }

        info!("Instance {} disconnected successfully", config_name);
        entry.state = ConfigState::Idle;
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
        if let Some(entry) = self.configs.get_mut(&config_name) {
            entry.state = ConfigState::Error { error };
        }
        Task::none()
    }

    // ========== Window Lifecycle Handlers ==========

    /// Handles window closed event - shuts down all connections and exits.
    pub fn handle_window_closed(&mut self, _window_id: iced::window::Id) -> Task<Message> {
        info!("Window closed, shutting down application");

        let shutdown_tasks: Vec<Task<Message>> = self
            .configs
            .iter_mut()
            .filter_map(|(name, entry)| {
                if let ConfigState::Connected { instance, .. } = &entry.state {
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

        for entry in self.configs.values_mut() {
            entry.state = ConfigState::Idle;
        }

        Task::batch(shutdown_tasks).chain(Task::future(exit()))
    }

    // ========== Confirmation Modal Handlers ==========

    /// Shows a confirmation modal with the given state.
    pub fn handle_show_confirmation(&mut self, state: ConfirmationState) -> Task<Message> {
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
                self.editor_state = None;
                Task::none()
            }
        }
    }

    /// Handles cancel action (user clicked Cancel).
    pub fn handle_cancel_confirmation(&mut self) -> Task<Message> {
        self.confirmation_state = None;
        Task::none()
    }

    /// Performs the actual deletion of a configuration.
    fn perform_delete_config(&mut self, config_name: String) -> Task<Message> {
        let Some(entry) = self.configs.get(&config_name) else {
            error!("Configuration not found: {}", config_name);
            return Task::none();
        };

        match fs::remove_file(&entry.config.path) {
            Ok(_) => {
                info!("Config file deleted: {}", entry.config.path.display());
            }
            Err(e) => {
                error!("Failed to delete config file: {}", e);
            }
        }

        self.configs.remove(&config_name);

        // If this was the selected config, clear the selection
        if self.selected_config.as_ref() == Some(&config_name) {
            self.selected_config = None;
        }

        Task::none()
    }
}

/// Exits the application gracefully.
async fn exit() -> Message {
    process::exit(0);
}
