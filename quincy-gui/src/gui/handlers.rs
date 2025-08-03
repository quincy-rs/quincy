use anyhow::Result;
use iced::widget::text_editor;
use iced::{window, Task};
use quincy::config::FromPath;
use std::fs;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use super::app::QuincyGui;
use super::types::QuincyInstance;
use super::types::{EditorWindow, Message, SelectedConfig};

impl QuincyGui {
    /// Handles selection of a configuration from the list.
    ///
    /// # Arguments
    /// * `name` - Name of the configuration to select
    ///
    /// # Returns
    /// Task::none() - No async task needed
    pub fn handle_config_selected(&mut self, name: String) -> Task<Message> {
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
    pub fn load_config_content(
        &self,
        config: &super::types::QuincyConfig,
    ) -> Result<SelectedConfig> {
        let config_content = fs::read_to_string(&config.path)?;
        let editable_content = text_editor::Content::with_text(&config_content);

        // Try to parse the configuration for display purposes
        let parsed_config = match quincy::config::ClientConfig::from_path(&config.path, "QUINCY_") {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                warn!("Failed to parse config {}: {}", config.name, e);
                None
            }
        };

        Ok(SelectedConfig {
            quincy_config: config.clone(),
            editable_content,
            parsed_config,
        })
    }

    /// Handles editing of the configuration text in editor window.
    ///
    /// # Arguments
    /// * `window_id` - ID of the editor window
    /// * `action` - Text editor action to perform
    ///
    /// # Returns
    /// Task::none() - No async task needed
    pub fn handle_config_edited(
        &mut self,
        window_id: window::Id,
        action: text_editor::Action,
    ) -> Task<Message> {
        if let Some(editor_window) = self.editor_windows.get_mut(&window_id) {
            // Apply the text editor action to update the content
            editor_window.content.perform(action);
            debug!("Text editor action applied to window {:?}", window_id);
        } else {
            error!("Editor window not found: {:?}", window_id);
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
    pub fn handle_config_name_changed(&mut self, new_name: String) -> Task<Message> {
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
    pub fn handle_config_name_saved(&mut self) -> Task<Message> {
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
    pub fn extract_old_config_name(&self, selected_config: &SelectedConfig) -> Option<String> {
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
    pub fn rename_config_file(
        &mut self,
        selected_config: &mut SelectedConfig,
        old_config_name: &str,
    ) {
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
    pub fn save_config_to_new_path(
        &mut self,
        selected_config: &mut SelectedConfig,
        new_path: &std::path::Path,
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

    /// Removes the old configuration file.
    ///
    /// # Arguments
    /// * `old_path` - Path to the old configuration file
    pub fn remove_old_config_file(&self, old_path: &std::path::Path) {
        match fs::remove_file(old_path) {
            Ok(_) => info!("Old config file removed: {}", old_path.display()),
            Err(e) => error!("Failed to remove old config file: {}", e),
        }
    }

    /// Handles deletion of the current configuration.
    ///
    /// # Returns
    /// Task::none() - No async task needed
    pub fn handle_config_delete(&mut self) -> Task<Message> {
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
    pub fn handle_new_config(&mut self) -> Task<Message> {
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
    pub fn generate_unique_config_name(&self) -> String {
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
    pub fn create_new_config(&self, name: &str) -> super::types::QuincyConfig {
        super::types::QuincyConfig {
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
    pub fn create_selected_config_with_template(
        &self,
        config: super::types::QuincyConfig,
    ) -> SelectedConfig {
        SelectedConfig {
            quincy_config: config,
            editable_content: text_editor::Content::with_text(include_str!(
                "../../../examples/client.toml"
            )),
            parsed_config: None,
        }
    }

    /// Saves a new configuration file to disk.
    ///
    /// # Arguments
    /// * `selected_config` - Configuration to save
    pub fn save_new_config_file(&self, selected_config: &SelectedConfig) {
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
    pub fn handle_connect(&mut self) -> Task<Message> {
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
    pub fn handle_disconnect(&mut self) -> Task<Message> {
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
    pub fn handle_update_metrics(&self) -> Task<Message> {
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

    /// Handles saving of the current configuration from editor window.
    ///
    /// # Arguments
    /// * `window_id` - ID of the editor window
    ///
    /// # Returns
    /// Task::none() - No async task needed
    pub fn handle_config_save_from_editor(&mut self, window_id: window::Id) -> Task<Message> {
        let config_content = match self.editor_windows.get(&window_id) {
            Some(editor_window) => editor_window.content.text(),
            None => {
                error!("Editor window not found: {:?}", window_id);
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

        // Update the main config content
        selected_config.editable_content = text_editor::Content::with_text(&config_content);

        // Save the file
        match fs::write(&selected_config.quincy_config.path, &config_content) {
            Ok(_) => {
                info!(
                    "Config file saved: {}",
                    selected_config.quincy_config.path.display()
                );
                // Try to re-parse the configuration after saving
                selected_config.parsed_config = match quincy::config::ClientConfig::from_path(
                    &selected_config.quincy_config.path,
                    "QUINCY_",
                ) {
                    Ok(cfg) => Some(cfg),
                    Err(e) => {
                        warn!(
                            "Failed to parse updated config {}: {}",
                            selected_config.quincy_config.name, e
                        );
                        None
                    }
                };

                // Update configs after successful save
                self.configs.insert(
                    selected_config.quincy_config.name.clone(),
                    selected_config.quincy_config.clone(),
                );

                // Close the editor window after successful save
                self.editor_modal_open = false;
                window::close(window_id)
            }
            Err(e) => {
                error!("Failed to save config file: {}", e);
                Task::none()
            }
        }
    }

    /// Handles opening the configuration editor in a separate window.
    ///
    /// # Returns
    /// Task to open editor window
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

        let (window_id, open_task) = window::open(window::Settings {
            size: iced::Size::new(800.0, 600.0),
            position: window::Position::Centered,
            min_size: Some(iced::Size::new(600.0, 400.0)),
            max_size: None,
            visible: true,
            resizable: true,
            decorations: true,
            transparent: false,
            level: window::Level::AlwaysOnTop,
            icon: None,
            platform_specific: window::settings::PlatformSpecific::default(),
            exit_on_close_request: true,
        });

        // Store the editor window info immediately
        let editor_window = EditorWindow {
            config_name,
            content: text_editor::Content::with_text(&config_content),
        };
        self.editor_windows.insert(window_id, editor_window);
        self.editor_modal_open = true;

        Task::batch([open_task.map(move |_| Message::EditorWindowOpened(window_id))])
    }

    /// Handles editor window opened event.
    ///
    /// # Arguments
    /// * `window_id` - ID of the opened editor window
    ///
    /// # Returns
    /// Task::none() - No async task needed
    pub fn handle_editor_window_opened(&mut self, window_id: window::Id) -> Task<Message> {
        if let Some(selected_config) = self.selected_config.as_ref() {
            let editor_window = EditorWindow {
                config_name: selected_config.quincy_config.name.clone(),
                content: text_editor::Content::with_text(&selected_config.editable_content.text()),
            };
            self.editor_windows.insert(window_id, editor_window);
            info!(
                "Editor window opened for config: {}",
                selected_config.quincy_config.name
            );
        }
        Task::none()
    }

    /// Handles window closed event - determines if it's main window or editor window.
    ///
    /// # Arguments
    /// * `window_id` - ID of the closed window
    ///
    /// # Returns
    /// Task for shutdown if main window, or Task::none() for editor windows
    pub fn handle_editor_window_closed(&mut self, window_id: window::Id) -> Task<Message> {
        // Check if this is the main window
        if Some(window_id) == self.main_window_id {
            return self.handle_main_window_closed();
        }

        // Otherwise, it's an editor window
        if let Some(editor_window) = self.editor_windows.remove(&window_id) {
            info!(
                "Editor window closed for config: {}",
                editor_window.config_name
            );
            // Re-enable main window interaction when editor is closed
            self.editor_modal_open = false;
        }
        Task::none()
    }

    /// Handles main window closed event - shuts down all connections and exits.
    ///
    /// # Returns
    /// Task to shutdown all connections and exit the application
    pub fn handle_main_window_closed(&mut self) -> Task<Message> {
        info!("Main window closed, shutting down application");

        // Disconnect all running instances
        let disconnect_tasks: Vec<_> = self
            .instances
            .iter()
            .map(|entry| {
                let config_name = entry.key().clone();
                info!("Shutting down instance: {}", config_name);
                config_name
            })
            .collect();

        // Create tasks to stop all instances
        let shutdown_tasks: Vec<Task<Message>> = disconnect_tasks
            .into_iter()
            .filter_map(|config_name| {
                if let Some((_, mut instance)) = self.instances.remove(&config_name) {
                    Some(Task::future(async move {
                        if let Err(e) = instance.stop().await {
                            error!("Failed to stop instance {}: {}", config_name, e);
                        }
                        Message::Disconnected
                    }))
                } else {
                    None
                }
            })
            .collect();

        // Exit the application after cleanup
        let exit_task = Task::future(async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            std::process::exit(0);
        });

        Task::batch([Task::batch(shutdown_tasks), exit_task])
    }
}
