//! Comprehensive error handling for the Quincy VPN system.
//!
//! This module provides a hierarchical error system using `thiserror` that covers
//! all aspects of the Quincy VPN, including authentication, networking, configuration,
//! and cryptographic operations. Error messages are designed to be informative for
//! debugging while avoiding exposure of sensitive information.

use std::net::IpAddr;
use std::path::PathBuf;
use thiserror::Error;

/// Main error type for the Quincy VPN system.
///
/// This enum represents all possible errors that can occur within the Quincy ecosystem,
/// organized by functional domains. Each variant maps to specific module errors while
/// maintaining a consistent interface for error handling throughout the application.
#[derive(Error, Debug)]
pub enum QuincyError {
    /// Authentication-related errors
    #[error("Authentication failed: {0}")]
    Auth(#[from] AuthError),

    /// Configuration-related errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Network-related errors
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Certificate and TLS-related errors
    #[error("Certificate error: {0}")]
    Certificate(#[from] CertificateError),

    /// QUIC protocol errors
    #[error("QUIC protocol error: {0}")]
    Quic(#[from] QuicError),

    /// Interface/TUN device errors
    #[error("Interface error: {0}")]
    Interface(#[from] InterfaceError),

    /// DNS configuration errors
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),

    /// Routing configuration errors
    #[error("Routing error: {0}")]
    Route(#[from] RouteError),

    /// Socket and low-level networking errors
    #[error("Socket error: {0}")]
    Socket(#[from] SocketError),

    /// I/O operations errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic system errors for unrecoverable conditions
    #[error("System error: {message}")]
    System { message: String },
}

/// Authentication and authorization errors.
///
/// These errors cover user authentication, credential validation, and authorization
/// failures. Messages are crafted to avoid leaking sensitive information while
/// providing enough detail for troubleshooting.
#[derive(Error, Debug)]
pub enum AuthError {
    /// Invalid credentials provided
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// User not found in authentication store
    #[error("User not found")]
    UserNotFound,

    /// Authentication timeout
    #[error("Authentication timeout")]
    Timeout,

    /// Malformed authentication payload
    #[error("Invalid authentication data format")]
    InvalidPayload,

    /// Permission denied for requested operation
    #[error("Permission denied")]
    PermissionDenied,

    /// Authentication store (e.g., users file) is unavailable
    #[error("Authentication store unavailable")]
    StoreUnavailable,

    /// Password hashing operation failed
    #[error("Password verification failed")]
    PasswordHashingFailed,

    /// Authentication stream communication error
    #[error("Authentication communication error")]
    StreamError,
}

/// Configuration loading and validation errors.
///
/// Covers errors in configuration file parsing, validation, and environment
/// variable processing. File paths may be included for debugging purposes.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// Configuration file not found
    #[error("Configuration file not found: {path}")]
    FileNotFound { path: PathBuf },

    /// Configuration file is not readable
    #[error("Cannot read configuration file: {path}")]
    FileNotReadable { path: PathBuf },

    /// Configuration file has invalid syntax
    #[error("Invalid configuration syntax in file: {path}")]
    InvalidSyntax { path: PathBuf },

    /// Missing required configuration field
    #[error("Missing required configuration field: {field}")]
    MissingField { field: String },

    /// Invalid value for configuration field
    #[error("Invalid value for field '{field}': {reason}")]
    InvalidValue { field: String, reason: String },

    /// Conflicting configuration options
    #[error("Conflicting configuration: {conflict}")]
    Conflict { conflict: String },

    /// Environment variable parsing error
    #[error("Invalid environment variable: {variable}")]
    InvalidEnvironmentVariable { variable: String },

    /// TOML deserialization error
    #[error("Configuration parsing error: {message}")]
    ParseError { message: String },
}

/// Network communication and protocol errors.
///
/// Encompasses all networking issues including connection failures, packet processing,
/// and protocol violations. IP addresses may be logged for debugging but are not
/// considered sensitive in this context.
#[derive(Error, Debug)]
pub enum NetworkError {
    /// Connection to remote peer failed
    #[error("Connection failed to {address}")]
    ConnectionFailed { address: String },

    /// Connection was unexpectedly closed
    #[error("Connection closed")]
    ConnectionClosed,

    /// Network timeout occurred
    #[error("Network operation timed out")]
    Timeout,

    /// Invalid network address or configuration
    #[error("Invalid network address: {address}")]
    InvalidAddress { address: String },

    /// Packet processing error
    #[error("Packet processing error: {reason}")]
    PacketError { reason: String },

    /// Network interface is not available
    #[error("Network interface unavailable: {interface}")]
    InterfaceUnavailable { interface: String },

    /// Address resolution failed
    #[error("Address resolution failed: {hostname}")]
    AddressResolution { hostname: String },

    /// Port binding failed
    #[error("Port binding failed: {port}")]
    PortBindFailed { port: u16 },

    /// Network is unreachable
    #[error("Network unreachable")]
    NetworkUnreachable,

    /// Maximum transmission unit exceeded
    #[error("MTU exceeded: packet size {size}, limit {limit}")]
    MtuExceeded { size: usize, limit: u16 },
}

/// Certificate and cryptographic operation errors.
///
/// Handles TLS certificate validation, loading, and cryptographic failures.
/// Certificate details are not exposed to prevent information leakage.
#[derive(Error, Debug)]
pub enum CertificateError {
    /// Certificate file could not be loaded
    #[error("Certificate loading failed: {path}")]
    LoadFailed { path: PathBuf },

    /// Private key file could not be loaded
    #[error("Private key loading failed: {path}")]
    PrivateKeyLoadFailed { path: PathBuf },

    /// Certificate validation failed
    #[error("Certificate validation failed")]
    ValidationFailed,

    /// Certificate has expired
    #[error("Certificate has expired")]
    Expired,

    /// Certificate is not yet valid
    #[error("Certificate is not yet valid")]
    NotYetValid,

    /// Certificate hostname verification failed
    #[error("Certificate hostname verification failed")]
    HostnameMismatch,

    /// Certificate chain is incomplete or invalid
    #[error("Invalid certificate chain")]
    InvalidChain,

    /// Certificate format is unsupported
    #[error("Unsupported certificate format")]
    UnsupportedFormat,

    /// Certificate authority is not trusted
    #[error("Untrusted certificate authority")]
    UntrustedCa,

    /// Certificate has been revoked
    #[error("Certificate has been revoked")]
    Revoked,
}

/// QUIC protocol specific errors.
///
/// Covers QUIC connection establishment, stream management, and protocol-specific
/// error conditions. These wrap underlying Quinn errors with more specific context.
#[derive(Error, Debug)]
pub enum QuicError {
    /// QUIC connection establishment failed
    #[error("QUIC connection failed: {reason}")]
    ConnectionFailed { reason: String },

    /// QUIC stream operation failed
    #[error("QUIC stream error: {reason}")]
    StreamError { reason: String },

    /// QUIC configuration error
    #[error("QUIC configuration error: {reason}")]
    ConfigError { reason: String },

    /// QUIC transport error
    #[error("QUIC transport error: {error_code}")]
    TransportError { error_code: u64 },

    /// QUIC application protocol error
    #[error("QUIC application error: {error_code}")]
    ApplicationError { error_code: u64 },

    /// QUIC idle timeout
    #[error("QUIC connection idle timeout")]
    IdleTimeout,

    /// QUIC endpoint configuration error
    #[error("QUIC endpoint configuration error")]
    EndpointError,

    /// QUIC datagram transmission error
    #[error("QUIC datagram error: {reason}")]
    DatagramError { reason: String },
}

/// TUN interface and virtual network device errors.
///
/// Handles errors related to TUN interface creation, configuration, and operation.
/// These errors often require administrative privileges to resolve.
#[derive(Error, Debug)]
pub enum InterfaceError {
    /// TUN interface creation failed
    #[error("TUN interface creation failed")]
    CreationFailed,

    /// Interface configuration failed
    #[error("Interface configuration failed: {reason}")]
    ConfigurationFailed { reason: String },

    /// Interface is not available or accessible
    #[error("Interface not available: {name}")]
    NotAvailable { name: String },

    /// Permission denied for interface operations
    #[error("Insufficient permissions for interface operations")]
    PermissionDenied,

    /// Interface I/O operation failed
    #[error("Interface I/O error: {operation}")]
    IoError { operation: String },

    /// Interface MTU setting failed
    #[error("MTU configuration failed: requested {requested}, supported {supported}")]
    MtuConfigFailed { requested: u16, supported: u16 },

    /// Interface is in wrong state for operation
    #[error("Interface in invalid state for operation: {state}")]
    InvalidState { state: String },

    /// Platform-specific interface error
    #[error("Platform interface error: {message}")]
    PlatformError { message: String },
}

/// DNS configuration and resolution errors.
///
/// Covers DNS server configuration, name resolution failures, and DNS-related
/// system configuration errors.
#[derive(Error, Debug)]
pub enum DnsError {
    /// DNS server configuration failed
    #[error("DNS server configuration failed")]
    ConfigurationFailed,

    /// DNS resolution failed
    #[error("DNS resolution failed for: {hostname}")]
    ResolutionFailed { hostname: String },

    /// DNS server is unreachable
    #[error("DNS server unreachable: {server}")]
    ServerUnreachable { server: IpAddr },

    /// DNS query timeout
    #[error("DNS query timeout")]
    QueryTimeout,

    /// Invalid DNS configuration
    #[error("Invalid DNS configuration: {reason}")]
    InvalidConfiguration { reason: String },

    /// DNS system configuration backup failed
    #[error("DNS configuration backup failed")]
    BackupFailed,

    /// DNS system configuration restore failed
    #[error("DNS configuration restore failed")]
    RestoreFailed,

    /// Platform-specific DNS error
    #[error("Platform DNS error: {message}")]
    PlatformError { message: String },
}

/// Routing table configuration errors.
///
/// Handles errors in route addition, removal, and routing table manipulation.
/// These operations typically require administrative privileges.
#[derive(Error, Debug)]
pub enum RouteError {
    /// Route addition failed
    #[error("Route addition failed: {destination}")]
    AddFailed { destination: String },

    /// Route removal failed
    #[error("Route removal failed: {destination}")]
    RemoveFailed { destination: String },

    /// Route table query failed
    #[error("Route table query failed")]
    QueryFailed,

    /// Invalid route specification
    #[error("Invalid route: {route}")]
    InvalidRoute { route: String },

    /// Route already exists
    #[error("Route already exists: {destination}")]
    AlreadyExists { destination: String },

    /// Route not found
    #[error("Route not found: {destination}")]
    NotFound { destination: String },

    /// Permission denied for routing operations
    #[error("Insufficient permissions for routing operations")]
    PermissionDenied,

    /// Platform-specific routing error
    #[error("Platform routing error: {message}")]
    PlatformError { message: String },
}

/// Socket operations and low-level networking errors.
///
/// Covers socket creation, binding, configuration, and low-level network operations
/// that don't fit into higher-level categories.
#[derive(Error, Debug)]
pub enum SocketError {
    /// Socket creation failed
    #[error("Socket creation failed")]
    CreationFailed,

    /// Socket binding failed
    #[error("Socket bind failed: {address}")]
    BindFailed { address: String },

    /// Socket configuration failed
    #[error("Socket configuration failed: {option}")]
    ConfigFailed { option: String },

    /// Socket buffer size setting failed
    #[error("Buffer size configuration failed: requested {requested}, actual {actual}")]
    BufferSizeFailed { requested: usize, actual: usize },

    /// Socket is in wrong state for operation
    #[error("Socket in invalid state: {state}")]
    InvalidState { state: String },

    /// Socket operation not supported on this platform
    #[error("Socket operation not supported: {operation}")]
    NotSupported { operation: String },

    /// Address already in use
    #[error("Address already in use: {address}")]
    AddressInUse { address: String },

    /// Address not available
    #[error("Address not available: {address}")]
    AddressNotAvailable { address: String },
}

// Conversion implementations for external crate errors

impl From<quinn::ConnectError> for QuincyError {
    fn from(err: quinn::ConnectError) -> Self {
        QuincyError::Quic(QuicError::ConnectionFailed {
            reason: err.to_string(),
        })
    }
}

impl From<quinn::ConnectionError> for QuincyError {
    fn from(err: quinn::ConnectionError) -> Self {
        match err {
            quinn::ConnectionError::TimedOut => QuincyError::Quic(QuicError::IdleTimeout),
            quinn::ConnectionError::ApplicationClosed(app_err) => {
                QuincyError::Quic(QuicError::ApplicationError {
                    error_code: app_err.error_code.into(),
                })
            }
            quinn::ConnectionError::TransportError(transport_err) => {
                QuincyError::Quic(QuicError::TransportError {
                    error_code: transport_err.code.into(),
                })
            }
            _ => QuincyError::Quic(QuicError::ConnectionFailed {
                reason: err.to_string(),
            }),
        }
    }
}

impl From<quinn::WriteError> for QuincyError {
    fn from(err: quinn::WriteError) -> Self {
        match err {
            quinn::WriteError::ConnectionLost(conn_err) => conn_err.into(),
            _ => QuincyError::Quic(QuicError::StreamError {
                reason: err.to_string(),
            }),
        }
    }
}

impl From<quinn::ReadError> for QuincyError {
    fn from(err: quinn::ReadError) -> Self {
        match err {
            quinn::ReadError::ConnectionLost(conn_err) => conn_err.into(),
            _ => QuincyError::Quic(QuicError::StreamError {
                reason: err.to_string(),
            }),
        }
    }
}

impl From<rustls::Error> for QuincyError {
    fn from(err: rustls::Error) -> Self {
        let cert_error = match err {
            rustls::Error::InvalidCertificate(_) => CertificateError::ValidationFailed,
            rustls::Error::NoCertificatesPresented => CertificateError::InvalidChain,
            rustls::Error::UnsupportedNameType => CertificateError::UnsupportedFormat,
            rustls::Error::DecryptError => CertificateError::ValidationFailed,
            rustls::Error::BadMaxFragmentSize => CertificateError::UnsupportedFormat,
            _ => CertificateError::ValidationFailed,
        };
        QuincyError::Certificate(cert_error)
    }
}

impl From<quinn::SendDatagramError> for QuincyError {
    fn from(err: quinn::SendDatagramError) -> Self {
        match err {
            quinn::SendDatagramError::UnsupportedByPeer => {
                QuincyError::Quic(QuicError::DatagramError {
                    reason: "Datagrams not supported by peer".to_string(),
                })
            }
            quinn::SendDatagramError::Disabled => QuincyError::Quic(QuicError::DatagramError {
                reason: "Datagrams disabled on connection".to_string(),
            }),
            quinn::SendDatagramError::TooLarge => QuincyError::Quic(QuicError::DatagramError {
                reason: "Datagram too large".to_string(),
            }),
            quinn::SendDatagramError::ConnectionLost(conn_err) => conn_err.into(),
        }
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for QuincyError {
    fn from(_err: tokio::sync::mpsc::error::SendError<T>) -> Self {
        QuincyError::system("Channel send failed: receiver dropped")
    }
}

impl From<tokio::task::JoinError> for QuincyError {
    fn from(err: tokio::task::JoinError) -> Self {
        if err.is_cancelled() {
            QuincyError::system("Task was cancelled")
        } else if err.is_panic() {
            QuincyError::system("Task panicked")
        } else {
            QuincyError::system(format!("Task failed: {err}"))
        }
    }
}

impl From<serde_json::Error> for QuincyError {
    fn from(err: serde_json::Error) -> Self {
        QuincyError::system(format!("JSON serialization/deserialization failed: {err}"))
    }
}

impl From<tracing::subscriber::SetGlobalDefaultError> for QuincyError {
    fn from(err: tracing::subscriber::SetGlobalDefaultError) -> Self {
        QuincyError::system(format!("Failed to set global tracing subscriber: {err}"))
    }
}

impl From<figment::Error> for QuincyError {
    fn from(err: figment::Error) -> Self {
        let config_error = if err.path.is_empty() {
            ConfigError::ParseError {
                message: err.to_string(),
            }
        } else {
            let path = PathBuf::from(err.path.join("."));
            match err.kind {
                figment::error::Kind::MissingField(field) => ConfigError::MissingField {
                    field: field.to_string(),
                },
                figment::error::Kind::InvalidType(_, _) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "invalid type".to_string(),
                },
                figment::error::Kind::InvalidLength(_, _) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "invalid length".to_string(),
                },
                figment::error::Kind::UnknownVariant(_, _) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "unknown variant".to_string(),
                },
                figment::error::Kind::UnknownField(..) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "unknown field".to_string(),
                },
                figment::error::Kind::UnsupportedKey(..) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "unsupported key".to_string(),
                },
                figment::error::Kind::ISizeOutOfRange(_) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "integer out of range".to_string(),
                },
                figment::error::Kind::Unsupported(_) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "unsupported value".to_string(),
                },
                figment::error::Kind::Message(_) => ConfigError::ParseError {
                    message: err.to_string(),
                },
                figment::error::Kind::InvalidValue(_, _) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "invalid value".to_string(),
                },
                figment::error::Kind::DuplicateField(_) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "duplicate field".to_string(),
                },
                figment::error::Kind::USizeOutOfRange(_) => ConfigError::InvalidValue {
                    field: path.to_string_lossy().to_string(),
                    reason: "integer out of range".to_string(),
                },
            }
        };
        QuincyError::Config(config_error)
    }
}

impl QuincyError {
    /// Creates a new QuincyError with a system message.
    ///
    /// This method is used for general system errors that do not fit into
    /// specific categories like authentication, network, or configuration errors.
    ///
    /// ### Arguments
    /// - `message` - A string message describing the system error.
    ///
    /// ### Returns
    /// A new `QuincyError::System` variant containing the provided message.
    pub fn system(message: impl Into<String>) -> Self {
        QuincyError::System {
            message: message.into(),
        }
    }

    /// Creates a QuincyError for invalid credentials.
    ///
    /// This method is specifically used when user authentication fails due to
    /// invalid credentials, such as incorrect username or password.
    ///
    /// ### Returns
    /// A new `QuincyError::Auth` variant with `AuthError::InvalidCredentials`.
    pub fn invalid_credentials() -> Self {
        QuincyError::Auth(AuthError::InvalidCredentials)
    }

    /// Creates a QuincyError for a failed network connection.
    ///
    /// This method is used when a connection to a remote address fails,
    /// such as when the server is unreachable or the connection is refused.
    ///
    /// ### Arguments
    /// - `address` - The address that the connection attempt failed for.
    ///
    /// ### Returns
    /// A new `QuincyError::Network` variant with `NetworkError::ConnectionFailed`.
    pub fn connection_failed(address: impl Into<String>) -> Self {
        QuincyError::Network(NetworkError::ConnectionFailed {
            address: address.into(),
        })
    }

    /// Creates a QuincyError for a configuration file not found.
    ///
    /// This method is used when the expected configuration file cannot be found
    /// on the filesystem, which is critical for the application to run.
    ///
    /// ### Arguments
    /// - `path` - The path to the configuration file that was not found.
    ///
    /// ### Returns
    /// A new `QuincyError::Config` variant with `ConfigError::FileNotFound`.
    pub fn config_file_not_found(path: impl Into<PathBuf>) -> Self {
        QuincyError::Config(ConfigError::FileNotFound { path: path.into() })
    }
}

/// Result type alias for Quincy operations.
///
/// This type alias provides a convenient shorthand for Results that use QuincyError
/// as the error type, promoting consistency across the codebase.
pub type Result<T> = std::result::Result<T, QuincyError>;
