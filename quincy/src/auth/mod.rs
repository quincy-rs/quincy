pub mod client;
pub mod server;
pub mod stream;
pub mod users_file;

use anyhow::Result;
use async_trait::async_trait;
use ipnet::IpNet;
use serde_json::Value;

use crate::server::address_pool::AddressPool;

/// Represents a user authenticator for the server.
///
/// `async_trait` is used to allow usage with dynamic dispatch.
#[async_trait]
pub trait ServerAuthenticator: Send + Sync {
    async fn authenticate_user(
        &self,
        address_pool: &AddressPool,
        authentication_payload: Value,
    ) -> Result<(String, IpNet)>;
}

/// Represents a user authentication payload generator for the client.
///
/// `async_trait` is used to allow usage with dynamic dispatch.
#[async_trait]
pub trait ClientAuthenticator: Send + Sync {
    async fn generate_payload(&self) -> Result<Value>;
}
