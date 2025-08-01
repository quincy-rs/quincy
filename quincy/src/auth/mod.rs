pub mod stream;

use anyhow::Result;
use async_trait::async_trait;
use ipnet::IpNet;
use serde_json::Value;

/// Represents a user authenticator for the server.
///
/// `async_trait` is used to allow usage with dynamic dispatch.
#[async_trait]
pub trait ServerAuthenticator: Send + Sync {
    async fn authenticate_user(&self, authentication_payload: Value) -> Result<(String, IpNet)>;
}

/// Represents a user authentication payload generator for the client.
///
/// `async_trait` is used to allow usage with dynamic dispatch.
#[async_trait]
pub trait ClientAuthenticator: Send + Sync {
    async fn generate_payload(&self) -> Result<Value>;
}
