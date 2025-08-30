use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use quincy::{
    auth::ClientAuthenticator, config::ClientAuthenticationConfig, error::AuthError, Result,
};

/// Authentication payload for users file authentication method
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsersFilePayload {
    username: String,
    password: String,
}

/// Client authenticator for users file based authentication
pub struct UsersFileClientAuthenticator {
    username: String,
    password: String,
}

impl UsersFileClientAuthenticator {
    /// Creates a new users file client authenticator
    ///
    /// # Arguments
    /// * `config` - Client authentication configuration containing credentials
    pub fn new(config: &ClientAuthenticationConfig) -> Self {
        Self {
            username: config.username.clone(),
            password: config.password.clone(),
        }
    }
}

#[async_trait]
impl ClientAuthenticator for UsersFileClientAuthenticator {
    async fn generate_payload(&self) -> Result<Value> {
        let payload = UsersFilePayload {
            username: self.username.clone(),
            password: self.password.clone(),
        };
        Ok(serde_json::to_value(payload).map_err(|_| AuthError::InvalidPayload)?)
    }
}
