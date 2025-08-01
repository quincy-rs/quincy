use anyhow::{anyhow, Result};
use ipnet::IpNet;
use quinn::Connection;
use std::time::Duration;
use tokio::time::timeout;

use quincy::auth::{
    stream::{AuthMessage, AuthStreamBuilder, AuthStreamMode},
    ServerAuthenticator,
};

/// Represents an authentication server handling initial authentication and session management.
pub struct AuthServer {
    authenticator: Box<dyn ServerAuthenticator>,
    server_address: IpNet,
    auth_timeout: Duration,
}

impl AuthServer {
    /// Creates a new `AuthServer` with a provided authenticator.
    pub fn new(
        authenticator: Box<dyn ServerAuthenticator>,
        server_address: IpNet,
        auth_timeout: Duration,
    ) -> Self {
        Self {
            authenticator,
            server_address,
            auth_timeout,
        }
    }

    /// Handles authentication for a client.
    ///
    /// ### Arguments
    /// - `connection` - The connection to the client
    pub async fn handle_authentication(&self, connection: &Connection) -> Result<(String, IpNet)> {
        let auth_stream_builder = AuthStreamBuilder::new(AuthStreamMode::Server);
        let mut auth_stream = auth_stream_builder
            .connect(connection, self.auth_timeout)
            .await?;

        let message = timeout(self.auth_timeout, auth_stream.recv_message()).await??;

        let auth_result = match message {
            AuthMessage::Authenticate { payload } => {
                let (username, client_address) =
                    self.authenticator.authenticate_user(payload).await?;

                auth_stream
                    .send_message(AuthMessage::Authenticated {
                        client_address,
                        server_address: self.server_address,
                    })
                    .await?;

                Ok((username, client_address))
            }
            _ => Err(anyhow!("authentication failed")),
        }?;

        auth_stream.close()?;

        Ok(auth_result)
    }
}
