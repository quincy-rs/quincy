use ipnet::IpNet;
use quincy::{QuincyError, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info};

use crate::gui::GuiError;

#[cfg(unix)]
use std::fs;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
use tokio::io::{ReadHalf, WriteHalf};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connection_duration: Duration,
    pub client_address: Option<IpNet>,
    pub server_address: Option<IpNet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(GuiError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStatus {
    pub status: ConnectionStatus,
    pub metrics: Option<ConnectionMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    StartClient { config_path: PathBuf },
    StopClient,
    GetStatus,
    StatusUpdate(ClientStatus),
    Error(GuiError),
    Shutdown,
}

pub struct IpcServer {
    #[cfg(unix)]
    listener: UnixListener,
    #[cfg(windows)]
    pipe_path: String,
}

impl IpcServer {
    pub fn new(socket_path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            // Ensure the parent directory exists
            if let Some(parent) = socket_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            // Remove existing socket file if it exists
            if socket_path.exists() {
                fs::remove_file(socket_path)?;
            }

            let listener = UnixListener::bind(socket_path)?;

            // Set socket file permissions to 0600 (user read/write only)
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(socket_path, permissions)?;

            info!("IPC server listening on: {:?}", socket_path);
            Ok(Self { listener })
        }

        #[cfg(windows)]
        {
            let pipe_path = format!(
                r"\\.\pipe\{}",
                socket_path.file_name().unwrap().to_string_lossy()
            );
            info!("IPC server will listen on: {}", pipe_path);
            Ok(Self { pipe_path })
        }
    }

    pub async fn accept(&self) -> Result<IpcConnection> {
        #[cfg(unix)]
        {
            let (stream, _) = self.listener.accept().await?;
            Ok(IpcConnection::new_unix(stream))
        }

        #[cfg(windows)]
        {
            let server = ServerOptions::new()
                .first_pipe_instance(true)
                .access_inbound(true)
                .reject_remote_clients(true)
                .create(&self.pipe_path)?;
            server.connect().await?;
            Ok(IpcConnection::new_windows_server(server))
        }
    }
}

pub struct IpcClient {
    connection: IpcConnection,
}

impl IpcClient {
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            debug!("Attempting to connect to IPC socket at: {:?}", socket_path);
            let stream = UnixStream::connect(socket_path).await.map_err(|e| {
                debug!(
                    "Failed to connect to Unix socket at {:?}: {}",
                    socket_path, e
                );
                e
            })?;
            let connection = IpcConnection::new_unix(stream);
            debug!("Successfully connected to IPC socket");
            Ok(Self { connection })
        }

        #[cfg(windows)]
        {
            let pipe_path = format!(
                r"\\.\pipe\{}",
                socket_path.file_name().unwrap().to_string_lossy()
            );
            let stream = ClientOptions::new().open(&pipe_path)?;
            let connection = IpcConnection::new_windows_client(stream);
            Ok(Self { connection })
        }
    }

    pub async fn send(&mut self, message: &IpcMessage) -> Result<()> {
        self.connection.send(message).await
    }

    pub async fn recv(&mut self) -> Result<IpcMessage> {
        self.connection.recv().await
    }
}

/// IPC connection with properly buffered reader for reliable message reception.
#[cfg(unix)]
pub struct IpcConnection {
    reader: BufReader<ReadHalf<UnixStream>>,
    writer: WriteHalf<UnixStream>,
}

#[cfg(windows)]
pub struct IpcConnection {
    inner: WindowsPipeConnection,
}

#[cfg(windows)]
enum WindowsPipeConnection {
    Server {
        reader: BufReader<tokio::io::ReadHalf<NamedPipeServer>>,
        writer: tokio::io::WriteHalf<NamedPipeServer>,
    },
    Client {
        reader: BufReader<tokio::io::ReadHalf<NamedPipeClient>>,
        writer: tokio::io::WriteHalf<NamedPipeClient>,
    },
}

impl IpcConnection {
    /// Creates a new IPC connection from a Unix stream.
    #[cfg(unix)]
    pub fn new_unix(stream: UnixStream) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(read_half),
            writer: write_half,
        }
    }

    /// Connects to an IPC server at the given path.
    #[cfg(unix)]
    pub async fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self::new_unix(stream))
    }

    /// Creates a new IPC connection from a Windows named pipe server.
    #[cfg(windows)]
    pub fn new_windows_server(stream: NamedPipeServer) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            inner: WindowsPipeConnection::Server {
                reader: BufReader::new(read_half),
                writer: write_half,
            },
        }
    }

    /// Creates a new IPC connection from a Windows named pipe client.
    #[cfg(windows)]
    pub fn new_windows_client(stream: NamedPipeClient) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            inner: WindowsPipeConnection::Client {
                reader: BufReader::new(read_half),
                writer: write_half,
            },
        }
    }

    /// Connects to an IPC server at the given path.
    #[cfg(windows)]
    pub async fn connect(path: &Path) -> Result<Self> {
        let pipe_name = path.to_string_lossy();
        let client = ClientOptions::new().open(&*pipe_name)?;
        Ok(Self::new_windows_client(client))
    }

    #[cfg(unix)]
    pub async fn send(&mut self, message: &IpcMessage) -> Result<()> {
        let json = serde_json::to_string(message)?;
        debug!("Sending IPC message: {}", json);

        self.writer.write_all(json.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await?;

        Ok(())
    }

    #[cfg(windows)]
    pub async fn send(&mut self, message: &IpcMessage) -> Result<()> {
        let json = serde_json::to_string(message)?;
        debug!("Sending IPC message: {}", json);

        match &mut self.inner {
            WindowsPipeConnection::Server { writer, .. } => {
                writer.write_all(json.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
            }
            WindowsPipeConnection::Client { writer, .. } => {
                writer.write_all(json.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
            }
        }

        Ok(())
    }

    #[cfg(unix)]
    pub async fn recv(&mut self) -> Result<IpcMessage> {
        let mut line = String::new();
        self.reader.read_line(&mut line).await?;

        if line.is_empty() {
            return Err(QuincyError::system("Connection closed"));
        }

        debug!("Received IPC message: {}", line.trim());
        let message: IpcMessage = serde_json::from_str(line.trim())?;
        Ok(message)
    }

    #[cfg(windows)]
    pub async fn recv(&mut self) -> Result<IpcMessage> {
        let mut line = String::new();

        match &mut self.inner {
            WindowsPipeConnection::Server { reader, .. } => {
                reader.read_line(&mut line).await?;
            }
            WindowsPipeConnection::Client { reader, .. } => {
                reader.read_line(&mut line).await?;
            }
        }

        if line.is_empty() {
            return Err(QuincyError::system("Connection closed"));
        }

        debug!("Received IPC message: {}", line.trim());
        let message: IpcMessage = serde_json::from_str(line.trim())?;
        Ok(message)
    }
}

pub fn get_ipc_socket_path(instance_name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        // Use XDG_RUNTIME_DIR if available and the directory exists
        if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
            let runtime_path = PathBuf::from(&runtime_dir);
            if runtime_path.exists() && runtime_path.is_dir() {
                return runtime_path.join(format!("quincy-{instance_name}.sock"));
            }
        }
        // Fall back to temp_dir if XDG_RUNTIME_DIR is not available
        env::temp_dir().join(format!("quincy-{instance_name}.sock"))
    }

    #[cfg(not(unix))]
    {
        env::temp_dir().join(format!("quincy-{instance_name}.sock"))
    }
}

pub fn get_log_file_path(instance_name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        // Use XDG_STATE_HOME (~/.local/state) for logs, or fall back to XDG_RUNTIME_DIR
        if let Ok(state_dir) = env::var("XDG_STATE_HOME") {
            let state_path = PathBuf::from(&state_dir);
            if state_path.exists() && state_path.is_dir() {
                return state_path.join(format!("quincy-{instance_name}.log"));
            }
        }
        if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
            let runtime_path = PathBuf::from(&runtime_dir);
            if runtime_path.exists() && runtime_path.is_dir() {
                return runtime_path.join(format!("quincy-{instance_name}.log"));
            }
        }
        env::temp_dir().join(format!("quincy-{instance_name}.log"))
    }

    #[cfg(not(unix))]
    {
        env::temp_dir().join(format!("quincy-{instance_name}.log"))
    }
}
