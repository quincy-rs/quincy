use std::time::Duration;

use bytes::BytesMut;
use ipnet::IpNet;
use quinn::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{io::AsyncReadExt, time::timeout};

use crate::{
    constants::AUTH_MESSAGE_BUFFER_SIZE,
    error::{AuthError, Result},
};

/// Represents an authentication message sent between the client and the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthMessage {
    /// Authentication request containing user credentials
    Authenticate { payload: Value },
    /// Successful authentication response with network configuration
    Authenticated {
        client_address: IpNet,
        server_address: IpNet,
    },
    /// Authentication failure response
    Failed,
}

/// Defines whether the auth stream is for client or server side
#[derive(Clone, Copy, Debug)]
pub enum AuthStreamMode {
    /// Client-side authentication stream
    Client,
    /// Server-side authentication stream
    Server,
}

/// Type marker for initialized auth stream state
pub struct Initialized;
/// Type marker for established auth stream state
pub struct Established;

/// Builder for creating authentication streams
pub struct AuthStreamBuilder {
    mode: AuthStreamMode,
}

/// Handles authentication communication over QUIC streams
pub struct AuthStream {
    send_stream: SendStream,
    recv_stream: RecvStream,
}

impl AuthStreamBuilder {
    /// Creates a new authentication stream builder
    ///
    /// # Arguments
    /// * `stream_mode` - Whether this is for client or server side
    pub fn new(stream_mode: AuthStreamMode) -> AuthStreamBuilder {
        AuthStreamBuilder { mode: stream_mode }
    }

    /// Establishes the authentication stream connection
    ///
    /// # Arguments
    /// * `connection` - The QUIC connection to use
    /// * `connection_timeout` - Timeout for stream establishment
    ///
    /// # Errors
    /// Returns `AuthError::StreamError` if stream establishment fails
    /// Returns `AuthError::Timeout` if the operation times out
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
            Ok(Err(_)) => Err(AuthError::StreamError),
            Err(_) => Err(AuthError::Timeout),
        }?;

        Ok(AuthStream {
            send_stream,
            recv_stream,
        })
    }
}

impl AuthStream {
    /// Sends an authentication message to the other side of the connection.
    ///
    /// # Arguments
    /// * `message` - The authentication message to send
    ///
    /// # Errors
    /// Returns `AuthError::InvalidPayload` if message serialization fails
    /// Returns `AuthError::StreamError` if network transmission fails
    pub async fn send_message(&mut self, message: AuthMessage) -> Result<()> {
        let serialized = serde_json::to_vec(&message).map_err(|_| AuthError::InvalidPayload)?;

        self.send_stream
            .write_all(&serialized)
            .await
            .map_err(|_| AuthError::StreamError)?;

        Ok(())
    }

    /// Receives an authentication message from the other side of the connection.
    ///
    /// # Errors
    /// Returns `AuthError::StreamError` if network reception fails
    /// Returns `AuthError::InvalidPayload` if message deserialization fails
    pub async fn recv_message(&mut self) -> Result<AuthMessage> {
        let mut buf = BytesMut::with_capacity(AUTH_MESSAGE_BUFFER_SIZE);
        self.recv_stream
            .read_buf(&mut buf)
            .await
            .map_err(|_| AuthError::StreamError)?;

        serde_json::from_slice(&buf).map_err(|_| AuthError::InvalidPayload.into())
    }

    /// Closes the authentication stream.
    ///
    /// This method consumes the stream and gracefully closes the connection.
    /// Network errors during close are ignored as the stream is being terminated.
    pub fn close(mut self) -> Result<()> {
        // Ignore the result of finish() since we're closing the stream anyway
        _ = self.send_stream.finish();

        Ok(())
    }
}
