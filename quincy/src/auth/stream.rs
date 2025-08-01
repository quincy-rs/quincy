use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use ipnet::IpNet;
use quinn::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{io::AsyncReadExt, time::timeout};

use crate::constants::AUTH_MESSAGE_BUFFER_SIZE;

/// Represents an authentication message sent between the client and the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthMessage {
    Authenticate {
        payload: Value,
    },
    Authenticated {
        client_address: IpNet,
        server_address: IpNet,
    },
    Failed,
}

#[derive(Clone, Copy, Debug)]
pub enum AuthStreamMode {
    Client,
    Server,
}

pub struct Initialized;
pub struct Established;

pub struct AuthStreamBuilder {
    mode: AuthStreamMode,
}

pub struct AuthStream {
    send_stream: SendStream,
    recv_stream: RecvStream,
}

impl AuthStreamBuilder {
    pub fn new(stream_mode: AuthStreamMode) -> AuthStreamBuilder {
        AuthStreamBuilder { mode: stream_mode }
    }

    pub async fn connect(
        self,
        connection: &Connection,
        connection_timeout: Duration,
    ) -> Result<AuthStream> {
        let stream_result = match self.mode {
            AuthStreamMode::Client => timeout(connection_timeout, connection.open_bi()).await,
            AuthStreamMode::Server => timeout(connection_timeout, connection.accept_bi()).await,
        };

        let (send_stream, recv_stream) = match stream_result {
            Ok(Ok(streams)) => Ok(streams),
            Ok(Err(_)) => Err(anyhow!(
                "failed to open authentication stream ({})",
                connection.remote_address().ip()
            )),
            Err(_) => Err(anyhow!(
                "connection timed out ({})",
                connection.remote_address().ip()
            )),
        }?;

        Ok(AuthStream {
            send_stream,
            recv_stream,
        })
    }
}

impl AuthStream {
    /// Sends an authentication message to the other side of the connection.
    pub async fn send_message(&mut self, message: AuthMessage) -> Result<()> {
        self.send_stream
            .write_all(&serde_json::to_vec(&message)?)
            .await
            .context("failed to send AuthMessage")
    }

    /// Receives an authentication message from the other side of the connection.
    pub async fn recv_message(&mut self) -> Result<AuthMessage> {
        let mut buf = BytesMut::with_capacity(AUTH_MESSAGE_BUFFER_SIZE);
        self.recv_stream.read_buf(&mut buf).await?;

        serde_json::from_slice(&buf).context("failed to parse AuthMessage JSON")
    }

    /// Closes the authentication stream.
    pub fn close(mut self) -> Result<()> {
        // Ignore the result of finish() since we're closing the stream anyway
        _ = self.send_stream.finish();

        Ok(())
    }
}
