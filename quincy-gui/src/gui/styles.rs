use iced::widget::button::{self, Status, Style as ButtonStyle};
use iced::widget::container;
use iced::widget::text_input::{self, Style as TextInputStyle};
use iced::{border, Background, Border, Color, Shadow, Theme, Vector};

/// Custom color palette for the modern dark theme.
pub struct ColorPalette;

impl ColorPalette {
    /// Dark background colors
    pub const BACKGROUND_PRIMARY: Color = Color::from_rgb(0.12, 0.12, 0.15); // #1E1E26
    pub const BACKGROUND_SECONDARY: Color = Color::from_rgb(0.15, 0.15, 0.18); // #262629
    pub const BACKGROUND_TERTIARY: Color = Color::from_rgb(0.18, 0.18, 0.22); // #2E2E38

    /// Blue accent colors
    pub const ACCENT_PRIMARY: Color = Color::from_rgb(0.27, 0.58, 0.92); // #4594EA (light blue)
    pub const ACCENT_SECONDARY: Color = Color::from_rgb(0.20, 0.47, 0.82); // #3378D1 (medium blue)
    pub const ACCENT_TERTIARY: Color = Color::from_rgb(0.15, 0.35, 0.65); // #2659A6 (darker blue)

    /// Text colors
    pub const TEXT_PRIMARY: Color = Color::from_rgb(0.95, 0.95, 0.95); // #F2F2F2
    pub const TEXT_SECONDARY: Color = Color::from_rgb(0.75, 0.75, 0.75); // #BFBFBF
    pub const TEXT_MUTED: Color = Color::from_rgb(0.55, 0.55, 0.55); // #8C8C8C

    /// Status colors
    pub const SUCCESS: Color = Color::from_rgb(0.2, 0.8, 0.4); // #33CC66
    pub const WARNING: Color = Color::from_rgb(0.9, 0.7, 0.2); // #E6B333
    pub const ERROR: Color = Color::from_rgb(0.8, 0.3, 0.3); // #CC4D4D

    /// Border and shadow colors
    pub const BORDER_LIGHT: Color = Color::from_rgb(0.35, 0.35, 0.35); // #595959
    pub const BORDER_DARK: Color = Color::from_rgb(0.25, 0.25, 0.25); // #404040
}

/// Custom button styles for the modern theme.
pub struct CustomButtonStyles;

impl CustomButtonStyles {
    /// Primary action button style (Connect/Disconnect)
    pub fn primary() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::ACCENT_PRIMARY)),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: ColorPalette::ACCENT_SECONDARY,
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 2.0),
                blur_radius: 4.0,
            },
        }
    }

    /// Primary button hover state
    pub fn primary_hovered() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::ACCENT_SECONDARY)),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: ColorPalette::ACCENT_TERTIARY,
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.27, 0.58, 0.92, 0.3),
                offset: Vector::new(0.0, 3.0),
                blur_radius: 8.0,
            },
        }
    }

    /// Primary button pressed state
    pub fn primary_pressed() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::ACCENT_TERTIARY)),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: ColorPalette::ACCENT_TERTIARY,
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 1.0),
                blur_radius: 2.0,
            },
        }
    }

    /// Secondary button style (Save, config selection buttons)
    pub fn secondary() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::BACKGROUND_TERTIARY)),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: ColorPalette::BORDER_LIGHT,
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 1.0),
                blur_radius: 2.0,
            },
        }
    }

    /// Secondary button hover state
    pub fn secondary_hovered() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::ACCENT_PRIMARY)),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: ColorPalette::ACCENT_SECONDARY,
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.27, 0.58, 0.92, 0.2),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 4.0,
            },
        }
    }

    /// Secondary button pressed state
    pub fn secondary_pressed() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::ACCENT_SECONDARY)),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: ColorPalette::ACCENT_TERTIARY,
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 1.0),
                blur_radius: 2.0,
            },
        }
    }

    /// Selected button style (currently selected config)
    pub fn selected() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::ACCENT_PRIMARY)),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: ColorPalette::ACCENT_SECONDARY,
                width: 2.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.27, 0.58, 0.92, 0.4),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 6.0,
            },
        }
    }

    /// Danger button style (Delete)
    pub fn danger() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::ERROR)),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: Color::from_rgb(0.7, 0.2, 0.2),
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 2.0),
                blur_radius: 4.0,
            },
        }
    }

    /// Danger button hover state
    pub fn danger_hovered() -> button::Style {
        button::Style {
            background: Some(Background::Color(Color::from_rgb(0.9, 0.2, 0.2))),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: Color::from_rgb(0.6, 0.15, 0.15),
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.8, 0.3, 0.3, 0.3),
                offset: Vector::new(0.0, 3.0),
                blur_radius: 8.0,
            },
        }
    }

    /// Disabled button style
    pub fn disabled() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::BACKGROUND_SECONDARY)),
            text_color: ColorPalette::TEXT_MUTED,
            border: Border {
                color: ColorPalette::BORDER_DARK,
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 0.0),
                blur_radius: 0.0,
            },
        }
    }
}

/// Custom container styles for the modern theme.
pub struct CustomContainerStyles;

impl CustomContainerStyles {
    /// Main panel container style
    pub fn panel() -> container::Style {
        container::Style {
            background: Some(Background::Color(ColorPalette::BACKGROUND_SECONDARY)),
            border: Border {
                color: ColorPalette::BORDER_LIGHT,
                width: 1.0,
                radius: border::Radius::from(8.0),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.3),
                offset: Vector::new(0.0, 4.0),
                blur_radius: 12.0,
            },
            text_color: Some(ColorPalette::TEXT_PRIMARY),
        }
    }

    /// Status section container style
    pub fn status_section() -> container::Style {
        container::Style {
            background: Some(Background::Color(ColorPalette::BACKGROUND_TERTIARY)),
            border: Border {
                color: ColorPalette::BORDER_LIGHT,
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.2),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 6.0,
            },
            text_color: Some(ColorPalette::TEXT_PRIMARY),
        }
    }

    /// Connected status highlight
    pub fn status_connected() -> container::Style {
        container::Style {
            background: Some(Background::Color(ColorPalette::BACKGROUND_TERTIARY)),
            border: Border {
                color: ColorPalette::SUCCESS,
                width: 2.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.2, 0.8, 0.4, 0.2),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 8.0,
            },
            text_color: Some(ColorPalette::TEXT_PRIMARY),
        }
    }

    /// Error status highlight
    pub fn status_error() -> container::Style {
        container::Style {
            background: Some(Background::Color(ColorPalette::BACKGROUND_TERTIARY)),
            border: Border {
                color: ColorPalette::ERROR,
                width: 2.0,
                radius: border::Radius::from(6.0),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.8, 0.3, 0.3, 0.2),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 8.0,
            },
            text_color: Some(ColorPalette::TEXT_PRIMARY),
        }
    }
}

/// Custom text input style for the modern theme.
pub struct CustomTextInputStyle;

impl CustomTextInputStyle {
    /// Default text input style
    pub fn base() -> text_input::Style {
        text_input::Style {
            background: Background::Color(ColorPalette::BACKGROUND_TERTIARY),
            border: Border {
                color: ColorPalette::BORDER_LIGHT,
                width: 1.0,
                radius: border::Radius::from(6.0),
            },
            icon: ColorPalette::TEXT_SECONDARY,
            placeholder: ColorPalette::TEXT_MUTED,
            value: ColorPalette::TEXT_PRIMARY,
            selection: ColorPalette::ACCENT_SECONDARY,
        }
    }

    /// Focused text input style
    pub fn focused() -> text_input::Style {
        text_input::Style {
            background: Background::Color(ColorPalette::BACKGROUND_TERTIARY),
            border: Border {
                color: ColorPalette::ACCENT_PRIMARY,
                width: 2.0,
                radius: border::Radius::from(6.0),
            },
            icon: ColorPalette::ACCENT_PRIMARY,
            placeholder: ColorPalette::TEXT_MUTED,
            value: ColorPalette::TEXT_PRIMARY,
            selection: ColorPalette::ACCENT_SECONDARY,
        }
    }
}

/// Style function types for iced components
impl CustomButtonStyles {
    /// Creates a style function for primary buttons
    pub fn primary_fn() -> impl Fn(&Theme, Status) -> ButtonStyle {
        |_theme, status| match status {
            Status::Active => Self::primary(),
            Status::Hovered => Self::primary_hovered(),
            Status::Pressed => Self::primary_pressed(),
            Status::Disabled => Self::disabled(),
        }
    }

    /// Creates a style function for secondary buttons
    pub fn secondary_fn() -> impl Fn(&Theme, Status) -> ButtonStyle {
        |_theme, status| match status {
            Status::Active => Self::secondary(),
            Status::Hovered => Self::secondary_hovered(),
            Status::Pressed => Self::secondary_pressed(),
            Status::Disabled => Self::disabled(),
        }
    }

    /// Creates a style function for selected buttons
    pub fn selected_fn() -> impl Fn(&Theme, Status) -> ButtonStyle {
        |_theme, status| match status {
            Status::Active | Status::Hovered | Status::Pressed => Self::selected(),
            Status::Disabled => Self::disabled(),
        }
    }

    /// Creates a style function for danger buttons
    pub fn danger_fn() -> impl Fn(&Theme, Status) -> ButtonStyle {
        |_theme, status| match status {
            Status::Active | Status::Pressed => Self::danger(),
            Status::Hovered => Self::danger_hovered(),
            Status::Disabled => Self::disabled(),
        }
    }
}

impl CustomTextInputStyle {
    /// Creates a style function for text inputs
    pub fn default_fn() -> impl Fn(&Theme, text_input::Status) -> TextInputStyle {
        |_theme, status| match status {
            text_input::Status::Active
            | text_input::Status::Hovered
            | text_input::Status::Disabled => Self::base(),
            text_input::Status::Focused => Self::focused(),
        }
    }
}
