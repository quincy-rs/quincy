use iced::widget::container as container_widget;
use iced::widget::container::Style as ContainerStyle;
use iced::widget::{row, stack, text};
use iced::{time, window, Background, Element, Length, Size, Subscription, Task, Theme};

/// Application icon embedded at compile time (Windows only)
#[cfg(target_os = "windows")]
const APP_ICON: &[u8] = include_bytes!("../../resources/icon.ico");

use super::styles::{ColorPalette, Layout, Spacing};
use quincy::{QuincyError, Result};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::result::Result as StdResult;
use std::time::Duration;
use tracing::error;

use super::types::{
    ConfigEntry, ConfigMsg, ConfigState, ConfirmMsg, ConfirmationState, EditorMsg, EditorState,
    InstanceMsg, Message, QuincyConfig, SystemMsg,
};
use crate::validation;

/// Main GUI application state for the Quincy VPN client.
///
/// This structure manages configuration files, connection states,
/// and the user interface state. It provides a graphical interface
/// for managing multiple VPN configurations and connections.
pub struct QuincyGui {
    /// Directory containing configuration files
    pub(crate) config_dir: PathBuf,
    /// All configurations with their runtime state, indexed by name (sorted)
    pub(crate) configs: BTreeMap<String, ConfigEntry>,
    /// Errors encountered while loading configurations from disk
    pub(crate) load_errors: Vec<String>,
    /// Name of the currently selected configuration (just a key into configs)
    pub(crate) selected_config: Option<String>,
    /// Editor modal state (Some when editor is open, None when closed)
    pub(crate) editor_state: Option<EditorState>,
    /// Confirmation modal state (Some when confirmation is open, None when closed)
    pub(crate) confirmation_state: Option<ConfirmationState>,
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

        (
            Self {
                config_dir,
                configs,
                load_errors,
                selected_config: None,
                editor_state: None,
                confirmation_state: None,
            },
            Task::none(),
        )
    }

    /// Returns the window settings for the application.
    ///
    /// # Returns
    /// Window settings with fixed size constraints and application icon (Windows only)
    pub fn window_settings() -> window::Settings {
        let window_size = Size::new(Layout::WINDOW_WIDTH, Layout::WINDOW_HEIGHT);

        #[cfg(target_os = "windows")]
        let icon = match window::icon::from_file_data(APP_ICON, None) {
            Ok(icon) => Some(icon),
            Err(e) => {
                error!("Failed to load application icon: {:?}", e);
                None
            }
        };
        #[cfg(not(target_os = "windows"))]
        let icon = None;

        window::Settings {
            min_size: Some(window_size),
            max_size: Some(window_size),
            size: window_size,
            icon,
            ..window::Settings::default()
        }
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
            Message::Config(msg) => match msg {
                ConfigMsg::Selected(name) => self.handle_config_selected(name),
                ConfigMsg::NameChanged(new_name) => self.handle_config_name_changed(new_name),
                ConfigMsg::NameSaved => self.handle_config_name_saved(),
                ConfigMsg::Delete => self.handle_config_delete(),
                ConfigMsg::New => self.handle_new_config(),
            },
            Message::Editor(msg) => match msg {
                EditorMsg::Action(action) => self.handle_editor_action(action),
                EditorMsg::Open => self.handle_open_editor(),
                EditorMsg::Close => self.handle_close_editor(),
                EditorMsg::Save => self.handle_save_editor(),
            },
            Message::Instance(msg) => match msg {
                InstanceMsg::Connect => self.handle_connect(),
                InstanceMsg::Disconnect => self.handle_disconnect(),
                InstanceMsg::CancelConnect => self.handle_cancel_connect(),
                InstanceMsg::Connected(config_name) => self.handle_connected(config_name),
                InstanceMsg::Disconnected => self.handle_disconnected(),
                InstanceMsg::StatusUpdated(name, status) => {
                    self.handle_status_updated(name, status)
                }
                InstanceMsg::DisconnectedWithError(name, error) => {
                    self.handle_disconnected_with_error(name, error)
                }
                InstanceMsg::ConnectedInstance(instance, metrics) => {
                    self.handle_connected_instance(instance, metrics)
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
            Message::Confirm(msg) => match msg {
                ConfirmMsg::Show(state) => self.handle_show_confirmation(state),
                ConfirmMsg::Confirm => self.handle_confirm(),
                ConfirmMsg::Cancel => self.handle_cancel_confirmation(),
            },
        }
    }

    /// Builds the main user interface view.
    ///
    /// This method creates the complete GUI layout with a left panel for
    /// configuration selection and a right panel for editing and monitoring.
    /// When the editor is open, it overlays the main content as a modal.
    ///
    /// # Returns
    /// Complete UI element tree for the application
    pub fn view(&self) -> Element<'_, Message> {
        let left_panel = self.build_config_selection_panel();
        let right_panel = self.build_config_details_panel();

        let main_content = container_widget(
            row![left_panel, right_panel]
                .spacing(Spacing::MD + 2.0)
                .padding(Spacing::XXL),
        )
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .width(Length::Fill)
        .height(Length::Fill);

        // Build stack layers based on which modals are open
        let has_editor = self.editor_state.is_some();
        let has_confirmation = self.confirmation_state.is_some();

        if !has_editor && !has_confirmation {
            return main_content.into();
        }

        let backdrop = container_widget(text(""))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_theme| ContainerStyle {
                background: Some(Background::Color(ColorPalette::BACKDROP_OVERLAY)),
                ..ContainerStyle::default()
            });

        // Editor modal with optional confirmation on top
        if has_editor && has_confirmation {
            let editor_modal = self.build_editor_modal();
            let confirmation_modal = self.build_confirmation_modal();
            stack![main_content, backdrop, editor_modal, confirmation_modal]
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        } else if has_editor {
            let editor_modal = self.build_editor_modal();
            stack![main_content, backdrop, editor_modal]
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        } else {
            let confirmation_modal = self.build_confirmation_modal();
            stack![main_content, backdrop, confirmation_modal]
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        }
    }

    /// Returns the window title for the application.
    ///
    /// # Returns
    /// Window title string
    pub fn title(&self) -> String {
        "Quincy VPN Client".to_string()
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
    /// * `Ok((BTreeMap, Vec<String>))` of configuration name to ConfigEntry and list of load error messages
    /// * `Err` if the config directory cannot be read
    ///
    /// # Errors
    /// Returns an error if the config directory cannot be read due to
    /// permissions or I/O issues
    fn load_configurations(
        config_dir: &Path,
    ) -> Result<(BTreeMap<String, ConfigEntry>, Vec<String>)> {
        let mut configs: BTreeMap<String, ConfigEntry> = BTreeMap::new();
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
                Some(Ok((name, entry))) => {
                    configs.insert(name, entry);
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
    /// Optional tuple of (config_name, ConfigEntry)
    fn process_config_entry(
        entry: StdResult<fs::DirEntry, io::Error>,
    ) -> Option<StdResult<(String, ConfigEntry), String>> {
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

        let config = QuincyConfig {
            name: config_name.clone(),
            path: config_path,
        };

        let entry = ConfigEntry {
            config,
            state: ConfigState::default(),
            parsed: None,
            parse_error: None,
        };

        Some(Ok((config_name, entry)))
    }
}
