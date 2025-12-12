use iced::widget::button::{self, Status, Style as ButtonStyle};
use iced::widget::container;
use iced::widget::text_input::{self, Style as TextInputStyle};
use iced::{border, Background, Border, Color, Shadow, Theme, Vector};

/// Typography scale for consistent font sizes across the application.
pub struct Typography;

impl Typography {
    /// Large title text (empty state headings)
    pub const TITLE_LARGE: f32 = 24.0;
    /// Icon/button text that needs emphasis
    pub const ICON_LARGE: f32 = 20.0;
    /// Modal and section titles
    pub const TITLE: f32 = 18.0;
    /// Section headers
    pub const HEADING: f32 = 16.0;
    /// Default body text, buttons, inputs
    pub const BODY: f32 = 14.0;
    /// Error details text
    pub const SMALL: f32 = 13.0;
    /// Secondary labels, captions
    pub const CAPTION: f32 = 12.0;
}

/// Spacing scale for consistent padding and margins.
pub struct Spacing;

impl Spacing {
    /// Extra small spacing (2px) - tight label/value pairs
    pub const XS: f32 = 2.0;
    /// Small spacing (4px) - within columns, tight groups
    pub const SM: f32 = 4.0;
    /// Button vertical padding (6px) - standard button vertical padding
    pub const BUTTON_V: f32 = 6.0;
    /// Medium spacing (8px) - button groups, modal sections, standard padding
    pub const MD: f32 = 8.0;
    /// Large spacing (12px) - section spacing, button padding horizontal
    pub const LG: f32 = 12.0;
    /// Extra large spacing (16px) - modal content padding
    pub const XL: f32 = 16.0;
    /// 2x extra large spacing (20px) - main layout padding
    pub const XXL: f32 = 20.0;
    /// 3x extra large spacing (24px) - large column gaps
    pub const XXXL: f32 = 24.0;
}

/// Layout dimensions for windows and modals.
pub struct Layout;

impl Layout {
    /// Main window width
    pub const WINDOW_WIDTH: f32 = 800.0;
    /// Main window height
    pub const WINDOW_HEIGHT: f32 = 610.0;
    /// Editor modal width
    pub const EDITOR_WIDTH: f32 = 700.0;
    /// Editor modal height
    pub const EDITOR_HEIGHT: f32 = 500.0;
}

/// Border radius values for consistent rounded corners.
pub struct BorderRadius;

impl BorderRadius {
    /// Standard radius for buttons, inputs
    pub const STANDARD: f32 = 6.0;
    /// Larger radius for panels, modals
    pub const LARGE: f32 = 8.0;
}

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

    /// Danger button color variants (derived from ERROR)
    pub const DANGER_HOVER: Color = Color::from_rgb(0.9, 0.2, 0.2);
    pub const DANGER_BORDER: Color = Color::from_rgb(0.7, 0.2, 0.2);
    pub const DANGER_BORDER_HOVER: Color = Color::from_rgb(0.6, 0.15, 0.15);

    /// Modal backdrop overlay
    pub const BACKDROP_OVERLAY: Color = Color::from_rgba(0.0, 0.0, 0.0, 0.6);

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
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 2.0),
                blur_radius: 4.0,
            },
            snap: false,
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
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.27, 0.58, 0.92, 0.3),
                offset: Vector::new(0.0, 3.0),
                blur_radius: 8.0,
            },
            snap: false,
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
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 1.0),
                blur_radius: 2.0,
            },
            snap: false,
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
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 1.0),
                blur_radius: 2.0,
            },
            snap: false,
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
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.27, 0.58, 0.92, 0.2),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 4.0,
            },
            snap: false,
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
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 1.0),
                blur_radius: 2.0,
            },
            snap: false,
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
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.27, 0.58, 0.92, 0.4),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 6.0,
            },
            snap: false,
        }
    }

    /// Danger button style (Delete)
    pub fn danger() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::ERROR)),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: ColorPalette::DANGER_BORDER,
                width: 1.0,
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 2.0),
                blur_radius: 4.0,
            },
            snap: false,
        }
    }

    /// Danger button hover state
    pub fn danger_hovered() -> button::Style {
        button::Style {
            background: Some(Background::Color(ColorPalette::DANGER_HOVER)),
            text_color: ColorPalette::TEXT_PRIMARY,
            border: Border {
                color: ColorPalette::DANGER_BORDER_HOVER,
                width: 1.0,
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.8, 0.3, 0.3, 0.3),
                offset: Vector::new(0.0, 3.0),
                blur_radius: 8.0,
            },
            snap: false,
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
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 0.0),
                blur_radius: 0.0,
            },
            snap: false,
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
                radius: border::Radius::from(BorderRadius::LARGE),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.3),
                offset: Vector::new(0.0, 4.0),
                blur_radius: 12.0,
            },
            text_color: Some(ColorPalette::TEXT_PRIMARY),
            snap: false,
        }
    }

    /// Status section container style
    pub fn status_section() -> container::Style {
        container::Style {
            background: Some(Background::Color(ColorPalette::BACKGROUND_TERTIARY)),
            border: Border {
                color: ColorPalette::BORDER_LIGHT,
                width: 1.0,
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.2),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 6.0,
            },
            text_color: Some(ColorPalette::TEXT_PRIMARY),
            snap: false,
        }
    }

    /// Connected status highlight
    pub fn status_connected() -> container::Style {
        container::Style {
            background: Some(Background::Color(ColorPalette::BACKGROUND_TERTIARY)),
            border: Border {
                color: ColorPalette::SUCCESS,
                width: 2.0,
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.2, 0.8, 0.4, 0.2),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 8.0,
            },
            text_color: Some(ColorPalette::TEXT_PRIMARY),
            snap: false,
        }
    }

    /// Error status highlight
    pub fn status_error() -> container::Style {
        container::Style {
            background: Some(Background::Color(ColorPalette::BACKGROUND_TERTIARY)),
            border: Border {
                color: ColorPalette::ERROR,
                width: 2.0,
                radius: border::Radius::from(BorderRadius::STANDARD),
            },
            shadow: Shadow {
                color: Color::from_rgba(0.8, 0.3, 0.3, 0.2),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 8.0,
            },
            text_color: Some(ColorPalette::TEXT_PRIMARY),
            snap: false,
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
                radius: border::Radius::from(BorderRadius::STANDARD),
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
                radius: border::Radius::from(BorderRadius::STANDARD),
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
    /// Always shows selected style regardless of button status (including disabled)
    pub fn selected_fn() -> impl Fn(&Theme, Status) -> ButtonStyle {
        |_theme, _status| Self::selected()
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
            text_input::Status::Focused { .. } => Self::focused(),
        }
    }
}
