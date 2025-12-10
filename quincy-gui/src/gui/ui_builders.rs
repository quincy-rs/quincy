use iced::alignment::Horizontal;
use iced::highlighter;
use iced::widget::container::Style as ContainerStyle;
use iced::widget::{
    button as button_widget, container as container_widget, text_input as text_input_widget,
};
use iced::widget::{column, opaque, row, scrollable, stack, text, text_editor};
use iced::{border, Alignment, Background, Border, Color, Element, Font, Length};

use super::app::QuincyGui;
use super::styles::{
    ColorPalette, CustomButtonStyles, CustomContainerStyles, CustomTextInputStyle,
};
use super::types::{ConfigMsg, ConfigState, ConfirmMsg, EditorMsg, InstanceMsg};
use super::types::{Message, SelectedConfig};
use super::utils::{format_bytes, format_duration};
use crate::ipc::ConnectionMetrics;

impl QuincyGui {
    /// Returns true if the editor modal is currently open.
    fn is_editor_open(&self) -> bool {
        self.editor_state.is_some()
    }

    /// Builds the confirmation modal overlay.
    ///
    /// This creates a centered modal dialog with a title, message, and Confirm/Cancel buttons.
    pub fn build_confirmation_modal(&self) -> Element<'_, Message> {
        let confirmation_state = match self.confirmation_state.as_ref() {
            Some(state) => state,
            None => {
                return container_widget(text(""))
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .into();
            }
        };

        // Title
        let title = text(&confirmation_state.title)
            .size(18)
            .color(ColorPalette::TEXT_PRIMARY);

        // Message
        let message = text(&confirmation_state.message)
            .size(14)
            .color(ColorPalette::TEXT_SECONDARY);

        // Action buttons
        let confirm_button =
            button_widget(text("Confirm").color(ColorPalette::TEXT_PRIMARY).size(14))
                .padding([6, 12])
                .on_press(Message::Confirm(ConfirmMsg::Confirm))
                .style(CustomButtonStyles::danger_fn());

        let cancel_button =
            button_widget(text("Cancel").color(ColorPalette::TEXT_PRIMARY).size(14))
                .padding([6, 12])
                .on_press(Message::Confirm(ConfirmMsg::Cancel))
                .style(CustomButtonStyles::secondary_fn());

        let button_row = row![cancel_button, confirm_button]
            .spacing(8)
            .align_y(Alignment::Center);

        // Modal content
        let modal_content = column![title, message, button_row]
            .spacing(16)
            .width(Length::Shrink)
            .height(Length::Shrink)
            .align_x(Alignment::Center);

        // Modal container with styling - smaller than editor modal
        let modal_box = container_widget(modal_content)
            .padding(16)
            .width(Length::Shrink)
            .height(Length::Shrink)
            .style(|_theme| ContainerStyle {
                background: Some(Background::Color(ColorPalette::BACKGROUND_PRIMARY)),
                border: Border {
                    color: ColorPalette::BORDER_LIGHT,
                    width: 1.0,
                    radius: border::Radius::from(8.0),
                },
                ..ContainerStyle::default()
            });

        // Backdrop to block interaction with content behind
        let backdrop = opaque(
            container_widget(text(""))
                .width(Length::Fill)
                .height(Length::Fill)
                .style(|_theme| ContainerStyle {
                    background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.6))),
                    ..ContainerStyle::default()
                }),
        );

        // Center the modal
        let centered_modal = container_widget(modal_box)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill);

        stack![backdrop, centered_modal]
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    /// Builds the editor modal overlay.
    ///
    /// This creates a centered modal dialog with the text editor and action buttons.
    pub fn build_editor_modal(&self) -> Element<'_, Message> {
        let editor_state = match self.editor_state.as_ref() {
            Some(state) => state,
            None => {
                return container_widget(text(""))
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .into();
            }
        };

        // Text editor with TOML syntax highlighting
        let editor = text_editor(&editor_state.content)
            .height(Length::Fill)
            .on_action(|action| Message::Editor(EditorMsg::Action(action)))
            .highlight("toml", highlighter::Theme::SolarizedDark)
            .font(Font::MONOSPACE);

        // Header with title
        let header = text(format!("Editing: {}", editor_state.config_name))
            .size(16)
            .color(ColorPalette::TEXT_PRIMARY);

        // Action buttons - matching main window style
        let save_button = button_widget(text("Save").color(ColorPalette::TEXT_PRIMARY).size(14))
            .padding([6, 12])
            .on_press(Message::Editor(EditorMsg::Save))
            .style(CustomButtonStyles::primary_fn());

        let cancel_button =
            button_widget(text("Cancel").color(ColorPalette::TEXT_PRIMARY).size(14))
                .padding([6, 12])
                .on_press(Message::Editor(EditorMsg::Close))
                .style(CustomButtonStyles::secondary_fn());

        let button_row = row![cancel_button, save_button]
            .spacing(8)
            .align_y(Alignment::Center);

        let header_row = row![header, button_row]
            .spacing(8)
            .align_y(Alignment::Center)
            .width(Length::Fill);

        // Modal content
        let modal_content = column![header_row, editor]
            .spacing(8)
            .width(Length::Fill)
            .height(Length::Fill);

        // Modal container with styling
        let modal_box = container_widget(modal_content)
            .padding(8)
            .width(Length::Fixed(700.0))
            .height(Length::Fixed(500.0))
            .style(|_theme| ContainerStyle {
                background: Some(Background::Color(ColorPalette::BACKGROUND_PRIMARY)),
                border: Border {
                    color: ColorPalette::BORDER_LIGHT,
                    width: 1.0,
                    radius: border::Radius::from(8.0),
                },
                ..ContainerStyle::default()
            });

        // Center the modal
        container_widget(modal_box)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }

    /// Builds the left panel containing configuration selection and new config button.
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
    pub fn build_config_button_list(&self) -> Element<'_, Message> {
        let configs = self.configs.keys().collect::<Vec<_>>();

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
    pub fn build_config_button<'a>(&self, name: &'a str) -> Element<'a, Message> {
        let is_editor_open = self.is_editor_open();

        // Check if any config has an active instance
        let has_active_instance = self
            .config_states
            .values()
            .any(|state| state.has_active_instance());

        let mut btn = button_widget(text(name).color(ColorPalette::TEXT_PRIMARY).size(14))
            .width(Length::Fill)
            .padding([6, 8]);

        // Only allow selection if editor is closed AND no config is active
        if !is_editor_open && !has_active_instance {
            btn = btn.on_press(Message::Config(ConfigMsg::Selected(name.to_string())));
        }

        let is_selected = self
            .selected_config
            .as_ref()
            .is_some_and(|config| config.quincy_config.name == name);

        // Style based on selection state, but show disabled for non-selected when locked
        if is_selected {
            btn.style(CustomButtonStyles::selected_fn())
        } else if is_editor_open || has_active_instance {
            // Disable non-selected buttons when editor is open or any config is active
            btn.style(|_theme, _status| CustomButtonStyles::disabled())
        } else {
            btn.style(CustomButtonStyles::secondary_fn())
        }
        .into()
    }

    /// Builds the "New Configuration" button.
    pub fn build_new_config_button(&self) -> Element<'_, Message> {
        let is_editor_open = self.is_editor_open();

        let mut btn = button_widget(
            text("+")
                .color(ColorPalette::TEXT_PRIMARY)
                .size(20)
                .center()
                .width(Length::Fill),
        )
        .width(Length::Fill)
        .padding([6, 8]);

        if !is_editor_open {
            btn = btn.on_press(Message::Config(ConfigMsg::New));
        }

        if is_editor_open {
            btn.style(|_theme, _status| CustomButtonStyles::disabled())
        } else {
            btn.style(CustomButtonStyles::secondary_fn())
        }
        .into()
    }

    /// Builds the right panel containing configuration details and controls.
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
    pub fn build_selected_config_content<'a>(
        &'a self,
        selected_config: &'a SelectedConfig,
    ) -> Element<'a, Message> {
        let config_name = &selected_config.quincy_config.name;
        let config_state = self
            .config_states
            .get(config_name)
            .cloned()
            .unwrap_or_default();

        let name_input = self.build_config_name_input(selected_config);
        let config_view = self.build_config_view_section(selected_config);
        let monitoring_section = self.build_monitoring_section_from_state(&config_state);
        let action_buttons = self.build_action_buttons_from_state(&config_state);

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
    pub fn build_config_name_input(
        &self,
        selected_config: &SelectedConfig,
    ) -> Element<'_, Message> {
        let is_editor_open = self.is_editor_open();

        let mut input =
            text_input_widget("Configuration name", &selected_config.quincy_config.name)
                .padding([6, 8])
                .size(14);

        if !is_editor_open {
            input = input
                .on_input(|s| Message::Config(ConfigMsg::NameChanged(s)))
                .on_submit(Message::Config(ConfigMsg::NameSaved));
        }

        input.style(CustomTextInputStyle::default_fn()).into()
    }

    /// Builds the configuration view section with read-only fields.
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
            let error_msg = selected_config
                .parse_error
                .clone()
                .unwrap_or_else(|| "Unknown error".to_string());
            column![
                text("Configuration parsing failed")
                    .size(14)
                    .color(ColorPalette::ERROR),
                text(error_msg).size(12).color(ColorPalette::TEXT_SECONDARY),
            ]
            .spacing(4)
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
        .style(|_theme| ContainerStyle {
            background: Some(Background::Color(ColorPalette::BACKGROUND_TERTIARY)),
            border: Border {
                color: ColorPalette::BORDER_LIGHT,
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            ..ContainerStyle::default()
        })
        .into()
    }

    /// Builds a single configuration field display with owned strings.
    pub fn build_owned_config_field(&self, label: String, value: String) -> Element<'_, Message> {
        column![
            text(label).size(12).color(ColorPalette::TEXT_SECONDARY),
            text(value).size(14).color(ColorPalette::TEXT_PRIMARY)
        ]
        .spacing(2)
        .into()
    }

    /// Builds the monitoring section from the ConfigState.
    pub fn build_monitoring_section_from_state(&self, state: &ConfigState) -> Element<'_, Message> {
        let (status_text, status_color, container_style, metrics) = match state {
            ConfigState::Idle => (
                "Disconnected".to_string(),
                ColorPalette::TEXT_SECONDARY,
                CustomContainerStyles::status_section(),
                None,
            ),
            ConfigState::Connecting { .. } => (
                "Connecting...".to_string(),
                ColorPalette::WARNING,
                CustomContainerStyles::status_section(),
                None,
            ),
            ConfigState::Connected { metrics, .. } => (
                "Connected".to_string(),
                ColorPalette::SUCCESS,
                CustomContainerStyles::status_connected(),
                metrics.as_ref(),
            ),
            ConfigState::Disconnecting => (
                "Disconnecting...".to_string(),
                ColorPalette::WARNING,
                CustomContainerStyles::status_section(),
                None,
            ),
            ConfigState::Error { error } => (
                error.to_string(),
                ColorPalette::ERROR,
                CustomContainerStyles::status_error(),
                None,
            ),
        };

        let mut content = vec![
            text("Connection Status")
                .size(16)
                .color(ColorPalette::TEXT_PRIMARY)
                .into(),
            text(status_text).size(14).color(status_color).into(),
        ];

        if let Some(metrics) = metrics {
            content.extend([
                container_widget(text("").size(4))
                    .height(Length::Fixed(8.0))
                    .into(),
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

    /// Builds the connection information display.
    pub fn build_connection_info(&self, metrics: &ConnectionMetrics) -> Element<'_, Message> {
        let mut ip_info = Vec::new();

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

    /// Builds the action buttons row based on ConfigState.
    pub fn build_action_buttons_from_state(&self, state: &ConfigState) -> Element<'_, Message> {
        let is_editor_open = self.is_editor_open();
        let is_active = state.has_active_instance();
        let is_connected = state.is_connected();
        let is_connecting = matches!(state, ConfigState::Connecting { .. });

        let connection_button = if is_connected {
            // Connected -> show Disconnect button
            let mut btn = button_widget(
                text("Disconnect")
                    .color(ColorPalette::TEXT_PRIMARY)
                    .size(14),
            )
            .padding([6, 12]);

            if !is_editor_open {
                btn = btn.on_press(Message::Instance(InstanceMsg::Disconnect));
            }

            if is_editor_open {
                btn.style(|_theme, _status| CustomButtonStyles::disabled())
            } else {
                btn.style(CustomButtonStyles::primary_fn())
            }
        } else if is_connecting {
            // Connecting -> show Cancel button
            button_widget(text("Cancel").color(ColorPalette::TEXT_PRIMARY).size(14))
                .padding([6, 12])
                .on_press(Message::Instance(InstanceMsg::CancelConnect))
                .style(CustomButtonStyles::danger_fn())
        } else if matches!(state, ConfigState::Disconnecting) {
            // Disconnecting -> show disabled button
            button_widget(
                text("Disconnecting...")
                    .color(ColorPalette::TEXT_MUTED)
                    .size(14),
            )
            .padding([6, 12])
            .style(|_theme, _status| CustomButtonStyles::disabled())
        } else {
            // Idle or Error -> show Connect button
            let mut btn = button_widget(text("Connect").color(ColorPalette::TEXT_PRIMARY).size(14))
                .padding([6, 12]);

            if !is_editor_open {
                btn = btn.on_press(Message::Instance(InstanceMsg::Connect));
            }

            if is_editor_open {
                btn.style(|_theme, _status| CustomButtonStyles::disabled())
            } else {
                btn.style(CustomButtonStyles::primary_fn())
            }
        };

        // Edit button - disabled when editor is open OR when instance is active
        let edit_button = if is_editor_open || is_active {
            button_widget(text("Edit").color(ColorPalette::TEXT_MUTED).size(14))
                .padding([6, 12])
                .style(|_theme, _status| CustomButtonStyles::disabled())
        } else {
            button_widget(text("Edit").color(ColorPalette::TEXT_PRIMARY).size(14))
                .padding([6, 12])
                .on_press(Message::Editor(EditorMsg::Open))
                .style(CustomButtonStyles::secondary_fn())
        };

        // Delete button - disabled when active or editor open
        let delete_button = if is_active || is_editor_open {
            button_widget(text("Delete").color(ColorPalette::TEXT_MUTED).size(14))
                .padding([6, 12])
                .style(|_theme, _status| CustomButtonStyles::disabled())
        } else {
            button_widget(text("Delete").color(ColorPalette::TEXT_PRIMARY).size(14))
                .padding([6, 12])
                .on_press(Message::Config(ConfigMsg::Delete))
                .style(CustomButtonStyles::danger_fn())
        };

        row![connection_button, edit_button, delete_button]
            .spacing(8)
            .width(Length::Fill)
            .into()
    }

    /// Builds the content shown when no configuration is selected.
    pub fn build_no_selection_content(&self) -> Element<'_, Message> {
        let mut contents: Vec<Element<'_, Message>> = vec![
            text("No configuration selected")
                .size(24)
                .color(ColorPalette::TEXT_SECONDARY)
                .align_x(Horizontal::Center)
                .width(Length::Fill)
                .into(),
            text("Select a configuration from the left panel or create a new one")
                .size(14)
                .color(ColorPalette::TEXT_MUTED)
                .align_x(Horizontal::Center)
                .width(Length::Fill)
                .into(),
        ];

        if !self.load_errors.is_empty() {
            contents.push(
                text("Configuration load errors")
                    .size(16)
                    .color(ColorPalette::ERROR)
                    .align_x(Horizontal::Center)
                    .width(Length::Fill)
                    .into(),
            );

            for err in &self.load_errors {
                contents.push(
                    text(err)
                        .size(13)
                        .color(ColorPalette::ERROR)
                        .align_x(Horizontal::Center)
                        .width(Length::Fill)
                        .into(),
                );
            }
        }

        container_widget(
            column(contents)
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
