use dashmap::DashMap;
use iced::widget::container as container_widget;
use iced::widget::{column, row, text};
use iced::{window, Background, Color, Element, Length, Task, Theme};
use quincy::{QuincyError, Result};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::error;

use super::styles::ColorPalette;
use super::types::QuincyInstance;
use super::types::{EditorWindow, Message, QuincyConfig, SelectedConfig};

/// Main GUI application state for the Quincy VPN client.
///
/// This structure manages configuration files, running VPN instances,
/// and the user interface state. It provides a graphical interface
/// for managing multiple VPN configurations and connections.
pub struct QuincyGui {
    /// Directory containing configuration files
    pub(crate) config_dir: PathBuf,
    /// Available VPN configurations indexed by name
    pub(crate) configs: HashMap<String, QuincyConfig>,
    /// Currently running VPN instances
    pub(crate) instances: Arc<DashMap<String, QuincyInstance>>,
    /// Currently selected configuration for editing
    pub(crate) selected_config: Option<SelectedConfig>,
    /// Editor windows for configuration editing
    pub(crate) editor_windows: BTreeMap<window::Id, EditorWindow>,
    /// Main window ID
    pub(crate) main_window_id: Option<window::Id>,
    /// Whether an editor window is currently open (for modal behavior)
    pub(crate) editor_modal_open: bool,
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

        let window_size = iced::Size::new(800.0, 610.0);

        // Create the main window
        let window_settings = window::Settings {
            min_size: Some(window_size),
            max_size: Some(window_size),
            size: window_size,
            ..window::Settings::default()
        };
        let (main_window_id, open_main_window) = window::open(window_settings);

        (
            Self {
                config_dir,
                configs,
                instances: Arc::new(DashMap::new()),
                selected_config: None,
                editor_windows: BTreeMap::new(),
                main_window_id: Some(main_window_id),
                editor_modal_open: false,
            },
            Task::batch([
                open_main_window.map(|_| Message::UpdateMetrics),
                Task::done(Message::UpdateMetrics),
            ]),
        )
    }

    /// Returns the theme to use for the application.
    ///
    /// # Returns
    /// Currently always returns Dark theme
    pub fn theme(&self, _window_id: window::Id) -> Theme {
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
            Message::ConfigEdited(window_id, action) => {
                self.handle_config_edited(window_id, action)
            }
            Message::ConfigNameChanged(new_name) => self.handle_config_name_changed(new_name),
            Message::ConfigNameSaved => self.handle_config_name_saved(),
            Message::ConfigSave(window_id) => self.handle_config_save_from_editor(window_id),
            Message::ConfigDelete => self.handle_config_delete(),
            Message::NewConfig => self.handle_new_config(),
            Message::OpenEditor => self.handle_open_editor(),
            Message::EditorWindowOpened(window_id) => self.handle_editor_window_opened(window_id),
            Message::EditorWindowClosed(window_id) => self.handle_editor_window_closed(window_id),
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
    pub fn view(&self, window_id: window::Id) -> Element<Message> {
        if Some(window_id) == self.main_window_id {
            // Main window view
            let left_panel = self.build_config_selection_panel();
            let right_panel = self.build_config_details_panel();

            let main_content =
                container_widget(row![left_panel, right_panel].spacing(10).padding(20))
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                    .width(Length::Fill)
                    .height(Length::Fill);

            // If editor modal is open, overlay a semi-transparent layer to indicate main window is disabled
            if self.editor_modal_open {
                container_widget(column![
                    main_content,
                    container_widget(
                        text("Editor window is open")
                            .size(16)
                            .color(ColorPalette::TEXT_SECONDARY)
                            .align_x(iced::alignment::Horizontal::Center)
                    )
                    .width(Length::Fill)
                    .center_x(Length::Fill)
                    .style(|_theme| iced::widget::container::Style {
                        background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.7))),
                        ..iced::widget::container::Style::default()
                    })
                ])
                .width(Length::Fill)
                .height(Length::Fill)
                .style(|_theme| iced::widget::container::Style {
                    background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.5))),
                    ..iced::widget::container::Style::default()
                })
                .into()
            } else {
                main_content.into()
            }
        } else {
            // Editor window view
            self.build_editor_window_view(window_id)
        }
    }

    /// Returns the window title for a given window.
    ///
    /// # Arguments
    /// * `window_id` - ID of the window
    ///
    /// # Returns
    /// Window title string
    pub fn title(&self, window_id: window::Id) -> String {
        if Some(window_id) == self.main_window_id {
            "Quincy VPN Client".to_string()
        } else if let Some(editor_window) = self.editor_windows.get(&window_id) {
            format!("Quincy Config Editor - {}", editor_window.config_name)
        } else {
            "Quincy Config Editor".to_string()
        }
    }

    /// Returns subscription for window events.
    ///
    /// # Returns
    /// Subscription for window close events
    pub fn subscription(&self) -> iced::Subscription<Message> {
        // Use a simple subscription that maps all close events to editor window closed
        // We'll handle main window detection in the update method
        window::close_events().map(Message::EditorWindowClosed)
    }

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
            return Err(QuincyError::system(format!(
                "Config directory path points to a file: {}",
                config_dir.display()
            )));
        }

        if !config_dir.exists() {
            fs::create_dir_all(config_dir).map_err(|e| {
                QuincyError::system(format!(
                    "Failed to create config directory {}: {}",
                    config_dir.display(),
                    e
                ))
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
                QuincyError::system(format!(
                    "Failed to read config directory {}: {}",
                    config_dir.display(),
                    e
                ))
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
        entry: std::result::Result<fs::DirEntry, std::io::Error>,
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
}
