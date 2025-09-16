use iced::widget::text_editor;
use iced::window;
use quincy::config::ClientConfig;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ipc::{ClientStatus, IpcConnection};

/// Represents a running Quincy VPN client instance.
///
/// Each instance manages a daemon process and IPC communication.
/// The instance tracks connection status and metrics for display in the GUI.
/// With the reversed architecture, connection loss naturally handles daemon lifecycle.
#[derive(Clone)]
pub struct QuincyInstance {
    /// Unique identifier for this instance
    pub name: String,
    /// IPC connection for communication with the daemon
    pub(crate) ipc_client: Option<Arc<Mutex<IpcConnection>>>,
    /// Current connection status and metrics
    pub(crate) status: ClientStatus,
}

impl fmt::Debug for QuincyInstance {
    /// Custom Debug implementation that excludes process handles and other non-debuggable fields.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    pub parsed_config: Option<ClientConfig>,
}

/// State for an editor window.
#[derive(Debug)]
pub struct EditorWindow {
    /// Name of the configuration being edited
    pub config_name: String,
    /// Text editor content with syntax highlighting
    pub content: text_editor::Content,
}

/// Domain-specific message groups to improve clarity.
#[derive(Debug, Clone)]
pub enum ConfigMsg {
    Selected(String),
    NameChanged(String),
    NameSaved,
    Save(window::Id),
    Delete,
    New,
}

#[derive(Debug, Clone)]
pub enum EditorMsg {
    Edited(window::Id, text_editor::Action),
    Open,
    WindowOpened(window::Id),
}

#[derive(Debug, Clone)]
pub enum InstanceMsg {
    Connect,
    Connected(String),
    ConnectedInstance(QuincyInstance),
    Disconnect,
    Disconnected,
    StatusUpdated(String, ClientStatus),
    DisconnectedWithError(String, String),
    ConnectFailed(String, String),
}

#[derive(Debug, Clone)]
pub enum SystemMsg {
    WindowClosed(window::Id),
    UpdateMetrics,
    Noop,
}

#[derive(Debug, Clone)]
pub enum Message {
    Config(ConfigMsg),
    Editor(EditorMsg),
    Instance(InstanceMsg),
    System(SystemMsg),
}
