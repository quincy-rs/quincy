//! GUI module for the Quincy VPN client.
//!
//! This module provides a graphical user interface for managing VPN configurations
//! and connections. It is split into multiple submodules for better organization:
//!
//! - `types`: Core data structures and message types
//! - `instance`: VPN instance management and IPC communication
//! - `app`: Main application logic and state management
//! - `handlers`: Event handlers for user interactions
//! - `ui_builders`: UI component builders and layout methods
//! - `styles`: Visual styling and theming
//! - `utils`: Utility functions for formatting and path handling

mod app;
mod error;
mod handlers;
mod instance;
mod styles;
mod types;
mod ui_builders;
mod utils;

// Re-export the main application struct and types
pub use app::QuincyGui;
pub use error::GuiError;
pub use types::{EditorState, Message, QuincyConfig, SelectedConfig};
pub use utils::{expand_path, format_bytes, format_duration};
