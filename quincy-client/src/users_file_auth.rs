use anyhow::Result;
use async_trait::async_trait;
use quincy::auth::ClientAuthenticator;
use quincy::config::ClientAuthenticationConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsersFilePayload {
    username: String,
    password: String,
}

pub struct UsersFileClientAuthenticator {
    username: String,
    password: String,
}

impl UsersFileClientAuthenticator {
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
        Ok(serde_json::to_value(payload)?)
    }
}
