use std::time::Duration;

use anyhow::{anyhow, Result};
use ipnet::IpNet;
use quinn::Connection;

use quincy::auth::{
    stream::{AuthMessage, AuthStreamBuilder, AuthStreamMode},
    ClientAuthenticator,
};

/// Represents an authentication client handling initial authentication and session management.
pub struct AuthClient {
    authenticator: Box<dyn ClientAuthenticator>,
    auth_timeout: Duration,
}

impl AuthClient {
    /// Creates a new `AuthClient` with a provided authenticator.
    pub fn new(authenticator: Box<dyn ClientAuthenticator>, auth_timeout: Duration) -> Self {
        Self {
            authenticator,
            auth_timeout,
        }
    }

    /// Establishes a session with the server.
    ///
    /// ### Arguments
    /// - `connection` - The connection to the server
    ///
    /// ### Returns
    /// - (IpNet, IpNet) - The client and server addresses
    pub async fn authenticate(&self, connection: &Connection) -> Result<(IpNet, IpNet)> {
        let auth_stream_builder = AuthStreamBuilder::new(AuthStreamMode::Client);
        let mut auth_stream = auth_stream_builder
            .connect(connection, self.auth_timeout)
            .await?;

        let authentication_payload = self.authenticator.generate_payload().await?;
        auth_stream
            .send_message(AuthMessage::Authenticate {
                payload: authentication_payload,
            })
            .await?;

        let auth_response = auth_stream.recv_message().await?;

        match auth_response {
            AuthMessage::Authenticated {
                client_address,
                server_address,
            } => Ok((client_address, server_address)),
            _ => Err(anyhow!("authentication failed")),
        }
    }
}
