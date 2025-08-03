use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
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
    Error(String),
    Shutdown,
    Heartbeat,
    HeartbeatAck,
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
                    std::fs::create_dir_all(parent)?;
                }
            }

            // Remove existing socket file if it exists
            if socket_path.exists() {
                std::fs::remove_file(socket_path)?;
            }

            let listener = UnixListener::bind(socket_path).map_err(|e| {
                error!("Failed to bind Unix socket at {:?}: {}", socket_path, e);
                e
            })?;

            // Set socket file permissions to be accessible by the original user
            // This is critical on macOS when daemon runs as root but GUI as user
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                // Make socket accessible by all users (owner, group, others can read/write)
                // This allows the user GUI to connect to the root daemon's socket
                if let Err(e) =
                    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))
                {
                    warn!("Failed to set socket permissions: {}", e);
                } else {
                    debug!("Set socket permissions to 0o666 for cross-user access");
                }
            }

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
                .first_pipe_instance(false)
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

pub enum IpcConnection {
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(windows)]
    WindowsServer(NamedPipeServer),
    #[cfg(windows)]
    WindowsClient(NamedPipeClient),
}

impl IpcConnection {
    #[cfg(unix)]
    pub fn new_unix(stream: UnixStream) -> Self {
        Self::Unix(stream)
    }

    #[cfg(windows)]
    pub fn new_windows_server(stream: NamedPipeServer) -> Self {
        Self::WindowsServer(stream)
    }

    #[cfg(windows)]
    pub fn new_windows_client(stream: NamedPipeClient) -> Self {
        Self::WindowsClient(stream)
    }

    pub async fn send(&mut self, message: &IpcMessage) -> Result<()> {
        let json = serde_json::to_string(message)?;
        debug!("Sending IPC message: {}", json);

        match self {
            #[cfg(unix)]
            Self::Unix(stream) => {
                stream.write_all(json.as_bytes()).await?;
                stream.write_all(b"\n").await?;
                stream.flush().await?;
            }
            #[cfg(windows)]
            Self::WindowsServer(stream) => {
                stream.write_all(json.as_bytes()).await?;
                stream.write_all(b"\n").await?;
                stream.flush().await?;
            }
            #[cfg(windows)]
            Self::WindowsClient(stream) => {
                stream.write_all(json.as_bytes()).await?;
                stream.write_all(b"\n").await?;
                stream.flush().await?;
            }
        }

        Ok(())
    }

    pub async fn recv(&mut self) -> Result<IpcMessage> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).await?;

                if line.is_empty() {
                    return Err(anyhow!("Connection closed"));
                }

                debug!("Received IPC message: {}", line.trim());
                let message: IpcMessage = serde_json::from_str(line.trim())?;
                Ok(message)
            }
            #[cfg(windows)]
            Self::WindowsServer(stream) => {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).await?;

                if line.is_empty() {
                    return Err(anyhow!("Connection closed"));
                }

                debug!("Received IPC message: {}", line.trim());
                let message: IpcMessage = serde_json::from_str(line.trim())?;
                Ok(message)
            }
            #[cfg(windows)]
            Self::WindowsClient(stream) => {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).await?;

                if line.is_empty() {
                    return Err(anyhow!("Connection closed"));
                }

                debug!("Received IPC message: {}", line.trim());
                let message: IpcMessage = serde_json::from_str(line.trim())?;
                Ok(message)
            }
        }
    }
}

pub fn get_ipc_socket_path(instance_name: &str) -> PathBuf {
    env::temp_dir().join(format!("quincy-{instance_name}.sock"))
}
