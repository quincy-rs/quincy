use iced::widget::text_editor;
use iced::window;
use std::path::PathBuf;

use crate::ipc::ClientStatus;

/// Represents a running Quincy VPN client instance.
///
/// Each instance manages a daemon process and IPC communication.
/// The instance tracks connection status and metrics for display in the GUI.
/// With the reversed architecture, connection loss naturally handles daemon lifecycle.
pub struct QuincyInstance {
    /// Unique identifier for this instance
    pub name: String,
    /// IPC connection for communication with the daemon
    pub(crate) ipc_client: Option<std::sync::Arc<tokio::sync::Mutex<crate::ipc::IpcConnection>>>,
    /// Current connection status and metrics
    pub(crate) status: ClientStatus,
}

impl std::fmt::Debug for QuincyInstance {
    /// Custom Debug implementation that excludes process handles and other non-debuggable fields.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuincyInstance")
            .field("name", &self.name)
            .field("status", &self.status)
            .finish()
    }
}

/// Configuration file information for a Quincy VPN client.
#[derive(Clone)]
pub struct QuincyConfig {
    /// Display name of the configuration
    pub name: String,
    /// File system path to the configuration file
    pub path: PathBuf,
}

/// Container for a selected configuration and its editable content.
pub struct SelectedConfig {
    /// The configuration metadata
    pub quincy_config: QuincyConfig,
    /// The text editor content for the configuration file
    pub editable_content: text_editor::Content,
    /// Parsed configuration for display
    pub parsed_config: Option<quincy::config::ClientConfig>,
}

/// State for an editor window.
#[derive(Debug)]
pub struct EditorWindow {
    /// Name of the configuration being edited
    pub config_name: String,
    /// Text editor content with syntax highlighting
    pub content: text_editor::Content,
}

/// Messages for GUI state updates and user interactions.
#[derive(Debug, Clone)]
pub enum Message {
    /// User selected a configuration from the list
    ConfigSelected(String),
    /// User edited the configuration text in editor window
    ConfigEdited(window::Id, text_editor::Action),
    /// User changed the configuration name
    ConfigNameChanged(String),
    /// User saved the configuration name change
    ConfigNameSaved,
    /// User requested to save the configuration from editor window
    ConfigSave(window::Id),
    /// User requested to delete the configuration
    ConfigDelete,
    /// User requested to create a new configuration
    NewConfig,
    /// User requested to open config editor in separate window
    OpenEditor,
    /// Editor window was opened
    EditorWindowOpened(window::Id),
    /// Editor window was closed
    EditorWindowClosed(window::Id),
    /// User requested to connect to a VPN
    Connect,
    /// VPN connection was established
    Connected(String),
    /// User requested to disconnect from VPN
    Disconnect,
    /// VPN was disconnected
    Disconnected,
    /// Periodic update of connection metrics
    UpdateMetrics,
}
