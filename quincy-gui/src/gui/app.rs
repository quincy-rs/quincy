use iced::widget::container as container_widget;
use iced::widget::container::Style as ContainerStyle;
use iced::widget::{column, row, text};
use iced::{
    alignment::Horizontal, time, window, Background, Color, Element, Length, Size, Subscription,
    Task, Theme,
};
use quincy::{QuincyError, Result};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::result::Result as StdResult;
use std::time::Duration;
use tracing::error;

use super::styles::ColorPalette;
use super::types::QuincyInstance;
use super::types::{ConfigMsg, EditorMsg, InstanceMsg, SystemMsg};
use super::types::{EditorWindow, Message, QuincyConfig, SelectedConfig};
use crate::ipc::ConnectionStatus;
use crate::validation;

/// Main GUI application state for the Quincy VPN client.
///
/// This structure manages configuration files, running VPN instances,
/// and the user interface state. It provides a graphical interface
/// for managing multiple VPN configurations and connections.
pub struct QuincyGui {
    /// Directory containing configuration files
    pub(crate) config_dir: PathBuf,
    /// Available VPN configurations indexed by name (kept sorted by key)
    pub(crate) configs: BTreeMap<String, QuincyConfig>,
    /// Errors encountered while loading configurations from disk
    pub(crate) load_errors: Vec<String>,
    /// Currently running VPN instances
    pub(crate) instances: HashMap<String, QuincyInstance>,
    /// Currently selected configuration for editing
    pub(crate) selected_config: Option<SelectedConfig>,
    /// Editor windows for configuration editing
    pub(crate) editor_windows: BTreeMap<window::Id, EditorWindow>,
    /// Main window ID
    pub(crate) main_window_id: Option<window::Id>,
    /// Whether an editor window is currently open (for modal behavior)
    pub(crate) editor_modal_open: bool,
    /// Last connection errors per configuration (for cases where no instance exists yet)
    pub(crate) last_errors: HashMap<String, String>,
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
            process::exit(1);
        }

        let (configs, load_errors) = match Self::load_configurations(&config_dir) {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to load configurations: {}", e);
                process::exit(1);
            }
        };

        let window_size = Size::new(800.0, 610.0);

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
                load_errors,
                instances: HashMap::new(),
                selected_config: None,
                editor_windows: BTreeMap::new(),
                main_window_id: Some(main_window_id),
                editor_modal_open: false,
                last_errors: HashMap::new(),
            },
            // Only open the main window; periodic updates are driven by Subscription
            open_main_window.map(|_| Message::System(SystemMsg::Noop)),
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
            Message::Config(msg) => match msg {
                ConfigMsg::Selected(name) => self.handle_config_selected(name),
                ConfigMsg::NameChanged(new_name) => self.handle_config_name_changed(new_name),
                ConfigMsg::NameSaved => self.handle_config_name_saved(),
                ConfigMsg::Save(window_id) => self.handle_config_save_from_editor(window_id),
                ConfigMsg::Delete => self.handle_config_delete(),
                ConfigMsg::New => self.handle_new_config(),
            },
            Message::Editor(msg) => match msg {
                EditorMsg::Edited(window_id, action) => {
                    self.handle_config_edited(window_id, action)
                }
                EditorMsg::Open => self.handle_open_editor(),
                EditorMsg::WindowOpened(window_id) => self.handle_editor_window_opened(window_id),
            },
            Message::Instance(msg) => match msg {
                InstanceMsg::Connect => self.handle_connect(),
                InstanceMsg::Disconnect => self.handle_disconnect(),
                InstanceMsg::Connected(config_name) => self.handle_connected(config_name),
                InstanceMsg::Disconnected => Task::none(),
                InstanceMsg::StatusUpdated(name, status) => {
                    if let Some(inst) = self.instances.get_mut(&name) {
                        let is_disconnect = matches!(status.status, ConnectionStatus::Disconnected);
                        if is_disconnect {
                            // Remove instance and record a brief error note
                            self.instances.remove(&name);
                            self.last_errors
                                .entry(name)
                                .or_insert_with(|| "Connection lost".to_string());
                        } else {
                            inst.status = status;
                        }
                    }
                    Task::none()
                }
                InstanceMsg::DisconnectedWithError(name, error) => {
                    self.instances.remove(&name);
                    self.last_errors.insert(name, error);
                    Task::none()
                }
                InstanceMsg::ConnectedInstance(instance) => {
                    let name = instance.name.clone();
                    self.instances.insert(name.clone(), instance);
                    self.handle_connected(name)
                }
                InstanceMsg::ConnectFailed(config_name, error) => {
                    self.handle_connect_failed(config_name, error)
                }
            },
            Message::System(msg) => match msg {
                SystemMsg::UpdateMetrics => self.handle_update_metrics(),
                SystemMsg::WindowClosed(window_id) => self.handle_window_closed(window_id),
                SystemMsg::Noop => Task::none(),
            },
        }
    }

    /// Builds the main user interface view.
    ///
    /// This method creates the complete GUI layout with a left panel for
    /// configuration selection and a right panel for editing and monitoring.
    ///
    /// # Returns
    /// Complete UI element tree for the application
    pub fn view(&self, window_id: window::Id) -> Element<'_, Message> {
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
                            .align_x(Horizontal::Center)
                    )
                    .width(Length::Fill)
                    .center_x(Length::Fill)
                    .style(|_theme| ContainerStyle {
                        background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.7))),
                        ..ContainerStyle::default()
                    })
                ])
                .width(Length::Fill)
                .height(Length::Fill)
                .style(|_theme| ContainerStyle {
                    background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.5))),
                    ..ContainerStyle::default()
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
    pub fn subscription(&self) -> Subscription<Message> {
        // Batch window close events with a 1s metrics tick
        let close_events =
            window::close_events().map(|id| Message::System(SystemMsg::WindowClosed(id)));
        let tick =
            time::every(Duration::from_secs(1)).map(|_| Message::System(SystemMsg::UpdateMetrics));
        Subscription::batch(vec![close_events, tick])
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
    /// * `Ok((HashMap, Vec<String>))` of configuration name to QuincyConfig and list of load error messages
    /// * `Err` if the config directory cannot be read
    ///
    /// # Errors
    /// Returns an error if the config directory cannot be read due to
    /// permissions or I/O issues
    fn load_configurations(
        config_dir: &Path,
    ) -> Result<(BTreeMap<String, QuincyConfig>, Vec<String>)> {
        let mut configs: BTreeMap<String, QuincyConfig> = BTreeMap::new();
        let mut errors: Vec<String> = Vec::new();

        let read_dir = fs::read_dir(config_dir).map_err(|e| {
            QuincyError::system(format!(
                "Failed to read config directory {}: {}",
                config_dir.display(),
                e
            ))
        })?;

        for entry_res in read_dir {
            match Self::process_config_entry(entry_res) {
                Some(Ok((name, cfg))) => {
                    configs.insert(name, cfg);
                }
                Some(Err(err_msg)) => {
                    errors.push(err_msg);
                }
                None => {}
            }
        }

        Ok((configs, errors))
    }

    /// Processes a single configuration file entry.
    ///
    /// # Arguments
    /// * `entry` - Directory entry result
    ///
    /// # Returns
    /// Optional tuple of (config_name, QuincyConfig)
    fn process_config_entry(
        entry: StdResult<fs::DirEntry, io::Error>,
    ) -> Option<StdResult<(String, QuincyConfig), String>> {
        let config_path = match entry {
            Ok(e) => e.path(),
            Err(e) => return Some(Err(format!("Failed to read a config entry: {}", e))),
        };

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

        // Validate sanitized config name using regex-based validator
        if let Err(e) = validation::validate_config_name(&config_name) {
            return Some(Err(format!("{} (file '{}')", e, config_file_name)));
        }

        let loaded_config = QuincyConfig {
            name: config_name.clone(),
            path: config_path,
        };

        Some(Ok((config_name, loaded_config)))
    }
}
