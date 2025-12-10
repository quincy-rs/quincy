use iced::widget::text_editor;
use iced::window;
use quincy::config::ClientConfig;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

use super::error::GuiError;
use crate::ipc::{ConnectionMetrics, IpcConnection};

/// Connection state machine for a VPN configuration.
///
/// This enum represents all possible states a configuration can be in,
/// making state transitions explicit and eliminating scattered state tracking.
#[derive(Debug, Clone, Default)]
pub enum ConfigState {
    /// No connection activity - idle state
    #[default]
    Idle,
    /// Connection is being established
    Connecting {
        /// When the connection attempt started
        started_at: Instant,
        /// The instance being connected (holds IPC connection for cancellation).
        /// None while spawning daemon, Some once IPC is established.
        instance: Option<QuincyInstance>,
    },
    /// Successfully connected to the VPN
    Connected {
        /// The active VPN instance
        instance: QuincyInstance,
        /// Connection metrics (bytes sent/received, duration, etc.)
        metrics: Option<ConnectionMetrics>,
    },
    /// Disconnection is in progress
    Disconnecting,
    /// An error occurred
    Error {
        /// Error to display
        error: GuiError,
    },
}

impl ConfigState {
    /// Returns true if the configuration is in a connected state.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }

    /// Returns true if the configuration is connecting or disconnecting.
    pub fn is_transitioning(&self) -> bool {
        matches!(self, Self::Connecting { .. } | Self::Disconnecting)
    }

    /// Returns true if the configuration has an active instance (connected or transitioning).
    pub fn has_active_instance(&self) -> bool {
        matches!(
            self,
            Self::Connecting { .. } | Self::Connected { .. } | Self::Disconnecting
        )
    }

    /// Returns the instance if connected, None otherwise.
    pub fn instance(&self) -> Option<&QuincyInstance> {
        match self {
            Self::Connected { instance, .. } => Some(instance),
            _ => None,
        }
    }

    /// Returns a mutable reference to the instance if connected.
    pub fn instance_mut(&mut self) -> Option<&mut QuincyInstance> {
        match self {
            Self::Connected { instance, .. } => Some(instance),
            _ => None,
        }
    }

    /// Returns the metrics if connected and available.
    pub fn metrics(&self) -> Option<&ConnectionMetrics> {
        match self {
            Self::Connected { metrics, .. } => metrics.as_ref(),
            _ => None,
        }
    }

    /// Returns the error if in error state.
    pub fn error(&self) -> Option<&GuiError> {
        match self {
            Self::Error { error } => Some(error),
            _ => None,
        }
    }
}

/// Represents a running Quincy VPN client instance.
///
/// Each instance manages the IPC connection to the daemon process.
/// Connection status and metrics are tracked separately in `ConfigState`.
#[derive(Clone)]
pub struct QuincyInstance {
    /// Unique identifier for this instance
    pub name: String,
    /// IPC connection for communication with the daemon
    pub(crate) ipc_client: Option<Arc<Mutex<IpcConnection>>>,
}

impl fmt::Debug for QuincyInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuincyInstance")
            .field("name", &self.name)
            .field("has_ipc", &self.ipc_client.is_some())
            .finish()
    }
}

impl QuincyInstance {
    /// Creates a new instance with the given name and IPC connection.
    pub fn new(name: String, ipc_client: Option<Arc<Mutex<IpcConnection>>>) -> Self {
        Self { name, ipc_client }
    }

    /// Returns a reference to the IPC client if available.
    pub fn ipc_client(&self) -> Option<&Arc<Mutex<IpcConnection>>> {
        self.ipc_client.as_ref()
    }

    /// Takes ownership of the IPC client, leaving None in its place.
    pub fn take_ipc_client(&mut self) -> Option<Arc<Mutex<IpcConnection>>> {
        self.ipc_client.take()
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
    /// Parsed configuration for display (None if parsing failed)
    pub parsed_config: Option<ClientConfig>,
    /// Parse error message if configuration failed to parse
    pub parse_error: Option<String>,
}

/// State for the inline editor modal.
#[derive(Debug)]
pub struct EditorState {
    /// Name of the configuration being edited
    pub config_name: String,
    /// Text editor content with syntax highlighting
    pub content: text_editor::Content,
}

/// State for confirmation dialogs
#[derive(Debug, Clone)]
pub struct ConfirmationState {
    pub title: String,
    pub message: String,
    pub confirm_action: ConfirmAction,
}

#[derive(Debug, Clone)]
pub enum ConfirmAction {
    DeleteConfig(String), // config name to delete
    DiscardEditorChanges,
}

/// Domain-specific message groups to improve clarity.
#[derive(Debug, Clone)]
pub enum ConfigMsg {
    Selected(String),
    NameChanged(String),
    NameSaved,
    Delete,
    New,
}

#[derive(Debug, Clone)]
pub enum ConfirmMsg {
    Show(ConfirmationState),
    Confirm,
    Cancel,
}

#[derive(Debug, Clone)]
pub enum EditorMsg {
    /// Text editor action (keystroke, selection, etc.)
    Action(text_editor::Action),
    /// Open the editor modal
    Open,
    /// Close the editor modal without saving
    Close,
    /// Save changes and close the editor modal
    Save,
}

/// Messages related to VPN instance lifecycle and status.
#[derive(Debug, Clone)]
pub enum InstanceMsg {
    /// User requested to connect the selected configuration
    Connect,
    /// Connection was successfully established (legacy, prefer ConnectedInstance)
    Connected(String),
    /// A new instance was created and connected with initial metrics
    ConnectedInstance(QuincyInstance, Option<ConnectionMetrics>),
    /// User requested to disconnect
    Disconnect,
    /// User requested to cancel an in-progress connection
    CancelConnect,
    /// Disconnection completed
    Disconnected,
    /// Status/metrics update received from daemon
    StatusUpdated(String, Option<ConnectionMetrics>),
    /// Connection was lost with an error
    DisconnectedWithError(String, GuiError),
    /// Connection attempt failed
    ConnectFailed(String, GuiError),
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
    Confirm(ConfirmMsg),
}
