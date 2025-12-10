//! Error types for the Quincy GUI.
//!
//! This module defines structured error types using thiserror for better
//! error handling and propagation through IPC and state machine.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// GUI-specific error type that can be serialized for IPC communication.
///
/// This error type is used throughout the GUI to represent various error
/// conditions that can occur during VPN operations. It is designed to be
/// both human-readable and machine-parseable.
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
pub enum GuiError {
    /// Authentication with the VPN server failed.
    #[error("Authentication failed: {reason}")]
    AuthFailed { reason: String },

    /// Network is unreachable or connection failed.
    #[error("Network unreachable: {details}")]
    NetworkUnreachable { details: String },

    /// Configuration is invalid or malformed.
    #[error("Configuration invalid: {field} - {reason}")]
    ConfigInvalid { field: String, reason: String },

    /// Connection was closed by the server or daemon.
    #[error("Connection closed: {reason}")]
    ConnectionClosed { reason: String },

    /// IPC communication error.
    #[error("IPC error: {0}")]
    Ipc(String),

    /// Daemon process error.
    #[error("Daemon error: {0}")]
    Daemon(String),

    /// Timeout waiting for connection or operation.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Permission denied or elevation required.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Generic or unknown error.
    #[error("{0}")]
    Other(String),
}

impl GuiError {
    /// Creates an authentication error.
    pub fn auth_failed(reason: impl Into<String>) -> Self {
        Self::AuthFailed {
            reason: reason.into(),
        }
    }

    /// Creates a network unreachable error.
    pub fn network_unreachable(details: impl Into<String>) -> Self {
        Self::NetworkUnreachable {
            details: details.into(),
        }
    }

    /// Creates a configuration invalid error.
    pub fn config_invalid(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ConfigInvalid {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Creates a connection closed error.
    pub fn connection_closed(reason: impl Into<String>) -> Self {
        Self::ConnectionClosed {
            reason: reason.into(),
        }
    }

    /// Creates an IPC error.
    pub fn ipc(msg: impl Into<String>) -> Self {
        Self::Ipc(msg.into())
    }

    /// Creates a daemon error.
    pub fn daemon(msg: impl Into<String>) -> Self {
        Self::Daemon(msg.into())
    }

    /// Creates a timeout error.
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::Timeout(msg.into())
    }

    /// Creates a permission denied error.
    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::PermissionDenied(msg.into())
    }

    /// Creates a generic error.
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

/// Conversion from standard errors to GuiError.
impl From<std::io::Error> for GuiError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::PermissionDenied => Self::permission_denied(err.to_string()),
            std::io::ErrorKind::TimedOut => Self::timeout(err.to_string()),
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted => Self::connection_closed(err.to_string()),
            _ => Self::other(err.to_string()),
        }
    }
}

/// Conversion from quincy::QuincyError to GuiError.
///
/// Maps QuincyError variants to appropriate GuiError variants where possible,
/// preserving the original error message without adding redundant prefixes.
impl From<quincy::QuincyError> for GuiError {
    fn from(err: quincy::QuincyError) -> Self {
        // Use the error's display message directly without wrapping
        // QuincyError already has well-formatted user-facing messages
        Self::Other(err.to_string())
    }
}

/// Conversion from serde_json errors to GuiError.
impl From<serde_json::Error> for GuiError {
    fn from(err: serde_json::Error) -> Self {
        Self::Other(format!("JSON error: {}", err))
    }
}
