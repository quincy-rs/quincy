use iced::alignment::Horizontal;
use iced::highlighter;
use iced::widget::{
    button as button_widget, container as container_widget, text_input as text_input_widget,
};
use iced::widget::{column, row, scrollable, text, text_editor};
use iced::{window, Background, Element, Length};

use super::app::QuincyGui;
use super::styles::{
    ColorPalette, CustomButtonStyles, CustomContainerStyles, CustomTextInputStyle,
};
use super::types::{Message, SelectedConfig};
use super::utils::{format_bytes, format_duration};
use crate::ipc::{ConnectionMetrics, ConnectionStatus};

impl QuincyGui {
    /// Builds the editor window view.
    ///
    /// # Arguments
    /// * `window_id` - ID of the editor window
    ///
    /// # Returns
    /// Element for the editor window
    pub fn build_editor_window_view(&self, window_id: window::Id) -> Element<'_, Message> {
        let editor_window = match self.editor_windows.get(&window_id) {
            Some(window) => window,
            None => {
                return container_widget(
                    text("Editor window not found")
                        .color(ColorPalette::ERROR)
                        .size(16),
                )
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .width(Length::Fill)
                .height(Length::Fill)
                .into();
            }
        };

        // Use the actual text editor with TOML syntax highlighting
        let editor = text_editor(&editor_window.content)
            .height(Length::Fill)
            .on_action(move |action| Message::ConfigEdited(window_id, action))
            .highlight("TOML", highlighter::Theme::SolarizedDark);

        let save_button = button_widget(text("Save").color(ColorPalette::TEXT_PRIMARY).size(14))
            .padding([8, 16])
            .on_press(Message::ConfigSave(window_id))
            .style(CustomButtonStyles::primary_fn());

        let header = row![
            text(format!("Editing: {}", editor_window.config_name))
                .size(18)
                .color(ColorPalette::TEXT_PRIMARY),
            save_button
        ]
        .spacing(16)
        .align_y(iced::Alignment::Center)
        .width(Length::Fill);

        container_widget(column![header, editor].spacing(16).height(Length::Fill))
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_theme| iced::widget::container::Style {
                background: Some(Background::Color(ColorPalette::BACKGROUND_PRIMARY)),
                ..iced::widget::container::Style::default()
            })
            .into()
    }

    /// Builds the left panel containing configuration selection and new config button.
    ///
    /// # Returns
    /// Container element with the configuration list
    pub fn build_config_selection_panel(&self) -> Element<'_, Message> {
        let config_buttons = self.build_config_button_list();
        let new_config_button = self.build_new_config_button();

        container_widget(
            column![config_buttons, new_config_button]
                .spacing(6)
                .height(Length::Fill)
                .clip(false),
        )
        .width(Length::FillPortion(1))
        .height(Length::Fill)
        .padding(8)
        .style(|_theme| CustomContainerStyles::panel())
        .into()
    }

    /// Builds the scrollable list of configuration buttons.
    ///
    /// # Returns
    /// Scrollable element containing configuration buttons
    pub fn build_config_button_list(&self) -> Element<'_, Message> {
        let mut configs = self.configs.keys().collect::<Vec<_>>();
        configs.sort();

        scrollable(
            column(
                configs
                    .into_iter()
                    .map(|name| self.build_config_button(name)),
            )
            .spacing(4),
        )
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
    pub fn build_config_button<'a>(&self, name: &'a str) -> Element<'a, Message> {
        let mut btn = button_widget(text(name).color(ColorPalette::TEXT_PRIMARY).size(14))
            .width(Length::Fill)
            .padding([6, 8]);

        // Disable button interactions when editor modal is open
        if !self.editor_modal_open {
            btn = btn.on_press(Message::ConfigSelected(name.to_string()));
        }

        let is_selected = self
            .selected_config
            .as_ref()
            .is_some_and(|config| config.quincy_config.name == name);

        if self.editor_modal_open {
            btn.style(|_theme, _status| CustomButtonStyles::disabled())
        } else if is_selected {
            btn.style(CustomButtonStyles::selected_fn())
        } else {
            btn.style(CustomButtonStyles::secondary_fn())
        }
        .into()
    }

    /// Builds the "New Configuration" button.
    ///
    /// # Returns
    /// Button element for creating new configurations
    pub fn build_new_config_button(&self) -> Element<'_, Message> {
        let mut btn = button_widget(
            text("+")
                .color(ColorPalette::TEXT_PRIMARY)
                .size(20)
                .center()
                .width(Length::Fill),
        )
        .width(Length::Fill)
        .padding([6, 8]);

        // Disable button when editor modal is open
        if !self.editor_modal_open {
            btn = btn.on_press(Message::NewConfig);
        }

        if self.editor_modal_open {
            btn.style(|_theme, _status| CustomButtonStyles::disabled())
        } else {
            btn.style(CustomButtonStyles::secondary_fn())
        }
        .into()
    }

    /// Builds the right panel containing configuration details and controls.
    ///
    /// # Returns
    /// Container element with configuration editing interface
    pub fn build_config_details_panel(&self) -> Element<'_, Message> {
        let content = if let Some(selected_config) = self.selected_config.as_ref() {
            self.build_selected_config_content(selected_config)
        } else {
            self.build_no_selection_content()
        };

        container_widget(content)
            .width(Length::FillPortion(3))
            .height(Length::Fill)
            .padding(8)
            .style(|_theme| CustomContainerStyles::panel())
            .into()
    }

    /// Builds the content for when a configuration is selected.
    ///
    /// # Arguments
    /// * `selected_config` - The currently selected configuration
    ///
    /// # Returns
    /// Column element with configuration editing interface
    pub fn build_selected_config_content<'a>(
        &'a self,
        selected_config: &'a SelectedConfig,
    ) -> Element<'a, Message> {
        let has_client = self
            .instances
            .contains_key(&selected_config.quincy_config.name);

        let name_input = self.build_config_name_input(selected_config);
        let config_view = self.build_config_view_section(selected_config);
        let monitoring_section = self.build_monitoring_section(selected_config, has_client);
        let action_buttons = self.build_action_buttons(has_client);

        column![
            container_widget(name_input).height(Length::Shrink),
            container_widget(config_view).height(Length::Shrink),
            container_widget(monitoring_section).height(Length::Shrink),
            container_widget(action_buttons).height(Length::Shrink)
        ]
        .spacing(8)
        .height(Length::Fill)
        .into()
    }

    /// Builds the configuration name input field.
    ///
    /// # Arguments
    /// * `selected_config` - The currently selected configuration
    ///
    /// # Returns
    /// Text input element for the configuration name
    pub fn build_config_name_input(
        &self,
        selected_config: &SelectedConfig,
    ) -> Element<'_, Message> {
        let mut input =
            text_input_widget("Configuration name", &selected_config.quincy_config.name)
                .padding([6, 8])
                .size(14);

        // Disable input when editor modal is open
        if !self.editor_modal_open {
            input = input
                .on_input(Message::ConfigNameChanged)
                .on_submit(Message::ConfigNameSaved);
        }

        input.style(CustomTextInputStyle::default_fn()).into()
    }

    /// Builds the configuration view section with read-only fields.
    ///
    /// # Arguments
    /// * `selected_config` - The currently selected configuration
    ///
    /// # Returns
    /// Container element with configuration view
    pub fn build_config_view_section(
        &self,
        selected_config: &SelectedConfig,
    ) -> Element<'_, Message> {
        let config_info = if let Some(ref config) = selected_config.parsed_config {
            let routes_display = if config.network.routes.is_empty() {
                "None".to_string()
            } else {
                format!(
                    "Routes: {}",
                    config
                        .network
                        .routes
                        .iter()
                        .map(|route| route.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            let dns_servers_display = if config.network.dns_servers.is_empty() {
                "None".to_string()
            } else {
                format!(
                    "DNS servers: {}",
                    config
                        .network
                        .dns_servers
                        .iter()
                        .map(|dns| dns.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };

            column![
                self.build_owned_config_field(
                    "Connection String".to_string(),
                    config.connection_string.clone()
                ),
                self.build_owned_config_field(
                    "Username".to_string(),
                    config.authentication.username.clone()
                ),
                self.build_owned_config_field(
                    "Encryption Type".to_string(),
                    format!("{:?}", config.crypto.key_exchange)
                ),
                self.build_owned_config_field("Routes".to_string(), routes_display),
                self.build_owned_config_field("DNS Servers".to_string(), dns_servers_display),
            ]
            .spacing(8)
        } else {
            column![
                text("Configuration parsing failed - use Edit to view raw content")
                    .size(14)
                    .color(ColorPalette::TEXT_MUTED)
            ]
        };

        container_widget(
            column![
                text("Configuration")
                    .size(16)
                    .color(ColorPalette::TEXT_PRIMARY),
                config_info
            ]
            .spacing(12)
            .height(Length::Shrink),
        )
        .padding(8)
        .width(Length::Fill)
        .height(Length::Shrink)
        .style(|_theme| iced::widget::container::Style {
            background: Some(Background::Color(ColorPalette::BACKGROUND_TERTIARY)),
            border: iced::Border {
                color: ColorPalette::BORDER_LIGHT,
                width: 1.0,
                radius: iced::border::Radius::from(6.0),
            },
            ..iced::widget::container::Style::default()
        })
        .into()
    }

    /// Builds a single configuration field display with owned strings.
    ///
    /// # Arguments
    /// * `label` - Field label
    /// * `value` - Field value
    ///
    /// # Returns
    /// Column element with label and value
    pub fn build_owned_config_field(&self, label: String, value: String) -> Element<'_, Message> {
        column![
            text(label).size(12).color(ColorPalette::TEXT_SECONDARY),
            text(value).size(14).color(ColorPalette::TEXT_PRIMARY)
        ]
        .spacing(2)
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
    pub fn build_monitoring_section(
        &self,
        selected_config: &SelectedConfig,
        has_client: bool,
    ) -> Element<'_, Message> {
        if has_client {
            if let Some(instance) = self.instances.get(&selected_config.quincy_config.name) {
                let status = instance.get_status();
                self.build_instance_status_display(&status.status, status.metrics.as_ref())
            } else {
                // Show loading status when client is starting
                self.build_instance_status_display(&ConnectionStatus::Connecting, None)
            }
        } else {
            // Always show disconnected status when no client is running
            self.build_instance_status_display(&ConnectionStatus::Disconnected, None)
        }
    }

    /// Builds the status display for a running instance.
    ///
    /// # Arguments
    /// * `status` - Current client status and metrics
    ///
    /// # Returns
    /// Column element with status information
    pub fn build_instance_status_display(
        &self,
        connection_status: &ConnectionStatus,
        metrics: Option<&ConnectionMetrics>,
    ) -> Element<'_, Message> {
        let status_text = match connection_status {
            ConnectionStatus::Connected => "Connected".to_string(),
            ConnectionStatus::Connecting => "Connecting...".to_string(),
            ConnectionStatus::Disconnected => "Disconnected".to_string(),
            ConnectionStatus::Error(err) => err.clone(),
        };

        let status_color = match connection_status {
            ConnectionStatus::Connected => ColorPalette::SUCCESS,
            ConnectionStatus::Connecting => ColorPalette::WARNING,
            ConnectionStatus::Disconnected => ColorPalette::TEXT_SECONDARY,
            ConnectionStatus::Error(_) => ColorPalette::ERROR,
        };

        let container_style = match connection_status {
            ConnectionStatus::Connected => CustomContainerStyles::status_connected(),
            ConnectionStatus::Error(_) => CustomContainerStyles::status_error(),
            _ => CustomContainerStyles::status_section(),
        };

        let mut content = vec![
            text("Connection Status")
                .size(16)
                .color(ColorPalette::TEXT_PRIMARY)
                .into(),
            text(status_text).size(14).color(status_color).into(),
        ];

        // Add metrics if available
        if let Some(metrics) = metrics {
            content.extend([
                container_widget(text("").size(4))
                    .height(Length::Fixed(8.0))
                    .into(), // Spacer
                text("Connection Details")
                    .size(14)
                    .color(ColorPalette::TEXT_SECONDARY)
                    .into(),
                self.build_connection_info(metrics),
            ]);
        }

        container_widget(column(content).spacing(4).height(Length::Shrink))
            .style(move |_theme| container_style)
            .padding(8)
            .width(Length::Fill)
            .height(Length::Shrink)
            .into()
    }

    /// Builds the connection information display with IP addresses at top and stats on the right.
    ///
    /// # Arguments
    /// * `metrics` - Connection metrics to display
    ///
    /// # Returns
    /// Row element with IP addresses/connection time on left and transfer stats on right
    pub fn build_connection_info(&self, metrics: &ConnectionMetrics) -> Element<'_, Message> {
        // Build IP addresses section
        let mut ip_info = Vec::new();

        // Add client IP address if available
        if let Some(client_addr) = metrics.client_address {
            ip_info.push(
                column![
                    text("Client IP")
                        .size(12)
                        .color(ColorPalette::TEXT_SECONDARY),
                    text(client_addr.to_string())
                        .size(14)
                        .color(ColorPalette::TEXT_PRIMARY),
                ]
                .spacing(2)
                .into(),
            );
        }

        // Add server IP address if available
        if let Some(server_addr) = metrics.server_address {
            ip_info.push(
                column![
                    text("Server IP")
                        .size(12)
                        .color(ColorPalette::TEXT_SECONDARY),
                    text(server_addr.to_string())
                        .size(14)
                        .color(ColorPalette::TEXT_PRIMARY),
                ]
                .spacing(2)
                .into(),
            );
        }

        // Add connection duration below IP addresses
        ip_info.push(
            column![
                text("Connected for")
                    .size(12)
                    .color(ColorPalette::TEXT_SECONDARY),
                text(format_duration(metrics.connection_duration))
                    .size(14)
                    .color(ColorPalette::TEXT_PRIMARY),
            ]
            .spacing(2)
            .into(),
        );

        let left_column = column(ip_info).spacing(2);

        // Build transfer statistics vertically on the right side
        let right_column = column![
            column![
                text("Upload").size(12).color(ColorPalette::TEXT_SECONDARY),
                text(format_bytes(metrics.bytes_sent))
                    .size(14)
                    .color(ColorPalette::ACCENT_PRIMARY),
            ]
            .spacing(2),
            column![
                text("Download")
                    .size(12)
                    .color(ColorPalette::TEXT_SECONDARY),
                text(format_bytes(metrics.bytes_received))
                    .size(14)
                    .color(ColorPalette::ACCENT_PRIMARY),
            ]
            .spacing(2)
        ]
        .spacing(2);

        row![left_column, right_column]
            .spacing(24)
            .width(Length::Fill)
            .into()
    }

    /// Builds the action buttons row (Connect/Disconnect, Edit, Delete).
    ///
    /// # Arguments
    /// * `has_client` - Whether a client instance is running
    ///
    /// # Returns
    /// Row element with action buttons
    pub fn build_action_buttons(&self, has_client: bool) -> Element<'_, Message> {
        let connection_button = if has_client {
            let mut btn = button_widget(
                text("Disconnect")
                    .color(ColorPalette::TEXT_PRIMARY)
                    .size(14),
            )
            .padding([6, 12]);

            if !self.editor_modal_open {
                btn = btn.on_press(Message::Disconnect);
            }

            if self.editor_modal_open {
                btn.style(|_theme, _status| CustomButtonStyles::disabled())
            } else {
                btn.style(CustomButtonStyles::primary_fn())
            }
        } else {
            let mut btn = button_widget(text("Connect").color(ColorPalette::TEXT_PRIMARY).size(14))
                .padding([6, 12]);

            if !self.editor_modal_open {
                btn = btn.on_press(Message::Connect);
            }

            if self.editor_modal_open {
                btn.style(|_theme, _status| CustomButtonStyles::disabled())
            } else {
                btn.style(CustomButtonStyles::primary_fn())
            }
        };

        let mut edit_button =
            button_widget(text("Edit").color(ColorPalette::TEXT_PRIMARY).size(14)).padding([6, 12]);

        // Disable edit button when editor modal is open
        if !self.editor_modal_open {
            edit_button = edit_button.on_press(Message::OpenEditor);
        }

        let edit_button = if self.editor_modal_open {
            edit_button.style(|_theme, _status| CustomButtonStyles::disabled())
        } else {
            edit_button.style(CustomButtonStyles::secondary_fn())
        };

        let delete_button = if has_client || self.editor_modal_open {
            // Disable delete button when client is running or editor modal is open
            button_widget(text("Delete").color(ColorPalette::TEXT_MUTED).size(14))
                .padding([6, 12])
                .style(|_theme, _status| CustomButtonStyles::disabled())
        } else {
            button_widget(text("Delete").color(ColorPalette::TEXT_PRIMARY).size(14))
                .padding([6, 12])
                .on_press(Message::ConfigDelete)
                .style(CustomButtonStyles::danger_fn())
        };

        row![connection_button, edit_button, delete_button]
            .spacing(8)
            .width(Length::Fill)
            .into()
    }

    /// Builds the content shown when no configuration is selected.
    ///
    /// # Returns
    /// Column element with "no selection" message
    pub fn build_no_selection_content(&self) -> Element<'_, Message> {
        container_widget(
            column![
                text("No configuration selected")
                    .size(24)
                    .color(ColorPalette::TEXT_SECONDARY)
                    .align_x(Horizontal::Center)
                    .width(Length::Fill),
                text("Select a configuration from the left panel or create a new one")
                    .size(14)
                    .color(ColorPalette::TEXT_MUTED)
                    .align_x(Horizontal::Center)
                    .width(Length::Fill)
            ]
            .spacing(8)
            .width(Length::Fill)
            .align_x(Horizontal::Center),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
    }
}
