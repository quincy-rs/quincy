use anyhow::Result;
use clap::Parser;
use iced::alignment::Horizontal;
use iced::widget::button::{danger, primary, secondary};
use iced::widget::container::Style;
use iced::widget::{button, column, container, row, scrollable, text, text_editor, text_input};
use iced::window::Settings;
use iced::{border, highlighter, Element, Length, Size, Task, Theme};
use quincy::client::QuincyClient;
use quincy::config::{ClientConfig, FromPath};
use quincy::network::interface::tun_rs::TunRsInterface;
use quincy::utils::tracing::log_subscriber;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{error, info};

/// The default configuration directory for Quincy, based on the operating system.
#[cfg(target_os = "windows")]
const DEFAULT_CONFIG_DIR: &str = "%AppData%/quincy";
#[cfg(unix)]
const DEFAULT_CONFIG_DIR: &str = "~/.config/quincy";

#[derive(Parser)]
#[command(name = "quincy")]
pub struct Args {
    #[arg(long, default_value = DEFAULT_CONFIG_DIR)]
    pub config_dir: PathBuf,
    #[arg(long, default_value = "QUINCY_")]
    pub env_prefix: String,
}

#[derive(Clone)]
struct QuincyInstance {
    name: String,
    client: Arc<Mutex<QuincyClient<TunRsInterface>>>,
}

impl QuincyInstance {
    async fn start(name: String, config_path: PathBuf) -> Result<Self> {
        let config = ClientConfig::from_path(&config_path, "QUINCY_")?;
        let mut client = QuincyClient::new(config);

        match timeout(Duration::from_secs(30), client.start()).await {
            Ok(Ok(())) => info!("Quincy client started successfully"),
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Timeout while starting Quincy client"));
            }
        }

        Ok(Self {
            name,
            client: Arc::new(Mutex::new(client)),
        })
    }

    async fn stop(&mut self) -> Result<()> {
        let mut client = self.client.lock().await;

        client.stop().await?;
        client.wait_for_shutdown().await?;

        Ok(())
    }
}

impl Debug for QuincyInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuincyInstance")
            .field("name", &self.name)
            .finish()
    }
}

#[derive(Clone)]
struct QuincyConfig {
    name: String,
    path: PathBuf,
}

struct SelectedConfig {
    quincy_config: QuincyConfig,
    editable_content: text_editor::Content,
}

struct QuincyGui {
    config_dir: PathBuf,
    configs: HashMap<String, QuincyConfig>,
    instances: HashMap<String, QuincyInstance>,
    selected_config: Option<SelectedConfig>,
}

#[derive(Debug, Clone)]
enum Message {
    ConfigSelected(String),
    ConfigEdited(text_editor::Action),
    ConfigNameChanged(String),
    ConfigNameSaved,
    ConfigSave,
    ConfigDelete,
    NewConfig,
    Connect,
    Connected(QuincyInstance),
    Disconnect,
    Disconnected,
}

impl QuincyGui {
    fn new() -> (Self, Task<Message>) {
        // Get config directory path
        let args = Args::parse();
        let config_dir = expand_path(&args.config_dir);

        if config_dir.is_file() {
            error!("Config directory is a file");
            exit(1);
        }

        // Create config directory if it doesn't exist
        if !config_dir.exists() {
            if let Err(e) = fs::create_dir_all(&config_dir) {
                error!("Failed to create config directory: {}", e);
                exit(1);
            }
        }

        let configs = fs::read_dir(&config_dir)
            .unwrap_or_else(|e| {
                error!("Failed to read config directory: {}", e);
                exit(1);
            })
            .filter_map(|entry| {
                let config_path = entry.ok()?.path();

                let config_file_name = config_path
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .expect("config file has file name");
                let config_name = config_file_name
                    .to_lowercase()
                    .strip_suffix(".toml")
                    .unwrap_or(&config_file_name)
                    .to_string();

                let loaded_config = QuincyConfig {
                    name: config_name.clone(),
                    path: config_path,
                };

                (config_name, loaded_config).into()
            })
            .collect::<HashMap<_, _>>();

        (
            Self {
                config_dir,
                configs,
                instances: HashMap::new(),
                selected_config: None,
            },
            Task::none(),
        )
    }

    fn title(&self) -> String {
        String::from("Quincy VPN Client")
    }

    fn theme(&self) -> Theme {
        // TODO: theme selector
        Theme::Dark
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ConfigSelected(name) => {
                if let Some(config) = self.configs.get(&name) {
                    let config_content = match fs::read_to_string(&config.path) {
                        Ok(content) => content,
                        Err(e) => {
                            error!("Failed to read config file: {}", e);
                            return Task::none();
                        }
                    };

                    let editable_content = text_editor::Content::with_text(&config_content);

                    self.selected_config = Some(SelectedConfig {
                        quincy_config: config.clone(),
                        editable_content,
                    });
                    info!("Config selected: {name}");
                } else {
                    error!("Configuration not found: {name}");
                }
            }
            Message::ConfigEdited(action) => {
                let selected_config = match self.selected_config.as_mut() {
                    Some(config) => config,
                    None => {
                        error!("No configuration selected");
                        return Task::none();
                    }
                };

                selected_config.editable_content.perform(action);
            }
            Message::ConfigNameChanged(new_name) => {
                let selected_config = match self.selected_config.as_mut() {
                    Some(config) => config,
                    None => {
                        error!("No configuration selected");
                        return Task::none();
                    }
                };

                selected_config.quincy_config.name = new_name;
            }
            Message::ConfigNameSaved => {
                let selected_config = match self.selected_config.as_mut() {
                    Some(config) => config,
                    None => {
                        error!("No configuration selected");
                        return Task::none();
                    }
                };

                let old_config_name = match selected_config.quincy_config.path.file_name() {
                    Some(name) => name.to_string_lossy().to_string(),
                    None => {
                        error!("Failed to get old config file name");
                        return Task::none();
                    }
                };
                let old_config_name = old_config_name
                    .to_lowercase()
                    .strip_suffix(".toml")
                    .unwrap_or(&old_config_name)
                    .to_string();

                self.configs.remove(&old_config_name);

                let old_path = selected_config.quincy_config.path.clone();
                let new_path = self
                    .config_dir
                    .join(format!("{}.toml", selected_config.quincy_config.name));

                match fs::write(&new_path, selected_config.editable_content.text()) {
                    Ok(_) => {
                        info!("Config file saved: {}", new_path.display());
                        selected_config.quincy_config.path = new_path;
                    }
                    Err(e) => {
                        error!("Failed to save config file: {}", e);
                    }
                }

                match fs::remove_file(&old_path) {
                    Ok(_) => {
                        info!("Old config file removed: {}", old_path.display());
                    }
                    Err(e) => {
                        error!("Failed to remove old config file: {}", e);
                    }
                }

                self.configs.insert(
                    selected_config.quincy_config.name.clone(),
                    selected_config.quincy_config.clone(),
                );
            }
            Message::ConfigSave => {
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
            }
            Message::ConfigDelete => {
                let selected_config = match self.selected_config.take() {
                    Some(config) => config,
                    None => {
                        error!("No configuration selected");
                        return Task::none();
                    }
                };

                if let Err(e) = fs::remove_file(&selected_config.quincy_config.path) {
                    error!("Failed to delete config file: {}", e);
                } else {
                    info!(
                        "Config file deleted: {}",
                        selected_config.quincy_config.path.display()
                    );
                }

                self.configs.remove(&selected_config.quincy_config.name);
            }
            Message::NewConfig => {
                let mut config_idx = 0;
                let mut new_config_name = "client_config".to_string();

                while self.configs.contains_key(&new_config_name) {
                    config_idx += 1;
                    new_config_name = format!("client_config_{}", config_idx);
                }

                let new_config = QuincyConfig {
                    name: new_config_name.clone(),
                    path: self.config_dir.join(format!("{new_config_name}.toml")),
                };

                let selected_config = SelectedConfig {
                    quincy_config: new_config.clone(),
                    editable_content: text_editor::Content::with_text(include_str!(
                        "../../examples/client.toml"
                    )),
                };

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
                self.configs.insert(new_config_name, new_config);
            }
            Message::Connect => {
                let selected_config = match self.selected_config.as_mut() {
                    Some(config) => config,
                    None => {
                        error!("No configuration selected");
                        return Task::none();
                    }
                };

                let config_name = selected_config.quincy_config.name.clone();
                let config_path = selected_config.quincy_config.path.clone();

                return Task::future(async move {
                    info!("Connecting to instance: {}", config_name);

                    match QuincyInstance::start(config_name.clone(), config_path).await {
                        Ok(instance) => {
                            info!("Instance {} connected", config_name);
                            Message::Connected(instance)
                        }
                        Err(e) => {
                            error!("Failed to start Quincy instance: {}", e);
                            Message::Disconnected
                        }
                    }
                });
            }
            Message::Disconnect => {
                let instance_config = match &self.selected_config {
                    Some(config) => config.quincy_config.clone(),
                    None => {
                        error!("No configuration selected");
                        return Task::none();
                    }
                };

                let mut client_instance = match self.instances.remove(&instance_config.name) {
                    Some(client) => client,
                    None => {
                        error!(
                            "No client instance found for configuration: {}",
                            instance_config.name
                        );
                        return Task::none();
                    }
                };

                info!("Instance {} disconnected", instance_config.name);

                return Task::future(async move {
                    match client_instance.stop().await {
                        Ok(_) => info!("Instance {} disconnected", instance_config.name),
                        Err(e) => error!("Failed to stop client instance: {}", e),
                    }

                    Message::Disconnected
                });
            }
            Message::Connected(instance) => {
                self.instances.insert(instance.name.clone(), instance);
            }
            Message::Disconnected => {}
        }

        Task::none()
    }

    fn view(&self) -> Element<Message> {
        let mut configs = self.configs.keys().collect::<Vec<_>>();
        configs.sort();

        // Left panel: Configuration selection
        let left_panel = container(
            column![
                scrollable(column(configs.into_iter().map(|name| {
                    let btn = button(text(name))
                        .width(Length::Fill)
                        .on_press(Message::ConfigSelected(name.clone()));

                    if self
                        .selected_config
                        .as_ref()
                        .is_some_and(|loaded_config| &loaded_config.quincy_config.name == name)
                    {
                        btn.style(primary)
                    } else {
                        btn.style(secondary)
                    }
                    .into()
                })))
                .height(Length::Fill),
                button(text("+").center().width(Length::Fill))
                    .width(Length::Fill)
                    .on_press(Message::NewConfig)
                    .style(secondary)
            ]
            .height(Length::Fill)
            .clip(false),
        )
        .width(Length::FillPortion(1))
        .height(Length::Fill)
        .style(Self::container_style);

        // Right panel: Configuration details
        let right_panel = container(
            if let Some(selected_config) = self.selected_config.as_ref() {
                let has_client = self
                    .instances
                    .contains_key(&selected_config.quincy_config.name);

                column![
                    text_input("Configuration name", &selected_config.quincy_config.name)
                        .on_input(Message::ConfigNameChanged)
                        .on_submit(Message::ConfigNameSaved),
                    text_editor(&selected_config.editable_content)
                        .on_action(Message::ConfigEdited)
                        .highlight("toml", highlighter::Theme::InspiredGitHub)
                        .height(Length::Fill),
                    row![
                        if has_client {
                            column![button(text("Disconnect"))
                                .on_press(Message::Disconnect)
                                .style(primary)]
                            .align_x(Horizontal::Left)
                        } else {
                            column![button(text("Connect"))
                                .on_press(Message::Connect)
                                .style(primary)]
                            .align_x(Horizontal::Left)
                        },
                        column![button(text("Save"))
                            .on_press(Message::ConfigSave)
                            .style(secondary)]
                        .align_x(Horizontal::Right),
                        column![button(text("Delete"))
                            .on_press(Message::ConfigDelete)
                            .style(danger)]
                        .align_x(Horizontal::Right),
                    ]
                    .width(Length::Fill)
                ]
                .spacing(10)
                .padding(20)
            } else {
                column![text("No configuration selected")
                    .size(24)
                    .align_x(Horizontal::Center)
                    .width(Length::Fill)]
                .spacing(10)
                .padding(20)
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(Horizontal::Center)
            },
        )
        .width(Length::FillPortion(3))
        .height(Length::Fill)
        .style(Self::container_style);

        // Main layout
        container(row![left_panel, right_panel].spacing(10).padding(20))
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    fn container_style(theme: &Theme) -> Style {
        let palette = theme.extended_palette();

        Style {
            background: Some(palette.background.weak.color.into()),
            border: border::rounded(3),
            ..Style::default()
        }
    }
}

// Utility function to expand home directory in paths
fn expand_path(path: &Path) -> PathBuf {
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

#[tokio::main]
async fn main() -> Result<()> {
    let _logger = tracing::subscriber::set_global_default(log_subscriber("info"));
    info!("Starting Quincy GUI client");

    let window_settings = Settings {
        min_size: Some(Size::new(600., 400.)),
        size: Size::new(800., 600.),
        ..Settings::default()
    };

    iced::application(QuincyGui::title, QuincyGui::update, QuincyGui::view)
        .window(window_settings)
        .theme(QuincyGui::theme)
        .run_with(QuincyGui::new)?;

    Ok(())
}
