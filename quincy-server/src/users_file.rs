use std::{
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
    sync::Arc,
};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use dashmap::DashMap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::server::address_pool::AddressPool;
use quincy::{
    auth::{ClientAuthenticator, ServerAuthenticator},
    config::{ClientAuthenticationConfig, ServerAuthenticationConfig},
    error::AuthError,
    Result,
};

pub struct UsersFileServerAuthenticator {
    user_database: UserDatabase,
    address_pool: Arc<AddressPool>,
}

pub struct UsersFileClientAuthenticator {
    username: String,
    password: String,
}

/// Authentication payload for users file authentication method
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsersFilePayload {
    username: String,
    password: String,
}

/// Represents a user database for authentication
pub struct UserDatabase {
    users: DashMap<String, User>,
    hasher: Argon2<'static>,
}

/// Represents a user with authentication information
pub struct User {
    pub username: String,
    pub password_hash: String,
}

impl UsersFileServerAuthenticator {
    /// Creates a new users file server authenticator
    ///
    /// # Arguments
    /// * `config` - Server authentication configuration
    /// * `address_pool` - Pool of available client IP addresses
    ///
    /// # Errors
    /// Returns `AuthError::StoreUnavailable` if the users file cannot be loaded
    pub fn new(
        config: &ServerAuthenticationConfig,
        address_pool: Arc<AddressPool>,
    ) -> Result<Self> {
        let users_file =
            load_users_file(&config.users_file).map_err(|_| AuthError::StoreUnavailable)?;
        let user_database = UserDatabase::new(users_file);

        Ok(Self {
            user_database,
            address_pool,
        })
    }
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
impl ServerAuthenticator for UsersFileServerAuthenticator {
    async fn authenticate_user(&self, authentication_payload: Value) -> Result<(String, IpNet)> {
        let payload: UsersFilePayload = serde_json::from_value(authentication_payload)
            .map_err(|_| AuthError::InvalidPayload)?;

        self.user_database
            .authenticate(&payload.username, payload.password)
            .await?;

        let client_address = self
            .address_pool
            .next_available_address()
            .ok_or(AuthError::StoreUnavailable)?;

        Ok((payload.username, client_address))
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

impl User {
    /// Creates a new `User` instance given the username and password hash.
    ///
    /// ### Arguments
    /// - `username` - the username
    /// - `password_hash` - a password hash representing the user's password
    pub fn new(username: String, password_hash: String) -> Self {
        Self {
            username,
            password_hash,
        }
    }
}

impl TryFrom<String> for User {
    type Error = quincy::QuincyError;

    fn try_from(user_string: String) -> Result<Self> {
        let split: Vec<String> = user_string.split(':').map(|str| str.to_owned()).collect();
        let name = split.first().ok_or(AuthError::InvalidPayload)?.clone();
        let password_hash_string = split.get(1).ok_or(AuthError::InvalidPayload)?.clone();

        Ok(User::new(name, password_hash_string))
    }
}

impl UserDatabase {
    /// Creates a new instance of the authentication module.
    ///
    /// ### Arguments
    /// - `users` - a map of users (username -> `User`)
    pub fn new(users: DashMap<String, User>) -> Self {
        Self {
            users,
            hasher: Argon2::default(),
        }
    }

    /// Authenticates the given user credentials.
    ///
    /// # Arguments
    /// * `username` - The username to authenticate
    /// * `password` - The password to verify
    ///
    /// # Errors
    /// Returns `AuthError::UserNotFound` if the user doesn't exist
    /// Returns `AuthError::InvalidCredentials` if the password is incorrect
    /// Returns `AuthError::PasswordHashingFailed` if password verification fails
    pub async fn authenticate(&self, username: &str, password: String) -> Result<()> {
        let user = self.users.get(username).ok_or(AuthError::UserNotFound)?;

        let password_hash =
            PasswordHash::new(&user.password_hash).map_err(|_| AuthError::PasswordHashingFailed)?;

        self.hasher
            .verify_password(password.as_bytes(), &password_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;

        Ok(())
    }
}

/// Loads the contents of a file with users and their password hashes into a map.
///
/// # Arguments
/// * `users_file` - Path to the users file
///
/// # Returns
/// A `DashMap` containing all loaded users
///
/// # Errors
/// Returns `AuthError::StoreUnavailable` if the file cannot be read or parsed
pub fn load_users_file(users_file: &Path) -> Result<DashMap<String, User>> {
    let file = File::open(users_file).map_err(|_| AuthError::StoreUnavailable)?;
    let lines = BufReader::new(file).lines();

    let result: DashMap<String, User> = DashMap::new();

    for line in lines {
        let line_content = line.map_err(|_| AuthError::StoreUnavailable)?;
        let user: User = line_content.try_into()?;
        result.insert(user.username.clone(), user);
    }

    Ok(result)
}

/// Writes the users and their password hashes into the specified file
///
/// # Arguments
/// * `users_file` - Path to the users file
/// * `users` - A map of users (username -> `User`)
///
/// # Errors
/// Returns `AuthError::StoreUnavailable` if the file cannot be written
pub fn save_users_file(users_file: &Path, users: DashMap<String, User>) -> Result<()> {
    if users_file.exists() {
        fs::remove_file(users_file).map_err(|_| AuthError::StoreUnavailable)?;
    }

    let file = File::create(users_file).map_err(|_| AuthError::StoreUnavailable)?;
    let mut writer = BufWriter::new(file);

    for (username, user) in users {
        writer
            .write_all(format!("{username}:{}\n", user.password_hash).as_bytes())
            .map_err(|_| AuthError::StoreUnavailable)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::users_file::{User, UserDatabase};
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};
    use dashmap::DashMap;
    use rand_core::OsRng;

    #[tokio::test]
    async fn test_authentication() {
        let users: DashMap<String, User> = DashMap::new();

        let argon = Argon2::default();
        let username = "test".to_owned();
        let password = "password".to_owned();
        let salt = SaltString::generate(&mut OsRng);

        let password_hash = argon.hash_password(password.as_bytes(), &salt).unwrap();

        let test_user = User::new(username.clone(), password_hash.to_string());
        users.insert(username.clone(), test_user);

        let user_db = UserDatabase::new(users);
        user_db
            .authenticate(&username, password)
            .await
            .expect("Credentials are valid");
    }
}
