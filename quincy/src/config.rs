use crate::certificates::{
    load_certificates_from_file, load_certificates_from_pem, load_private_key_from_file,
};
use crate::constants::{
    QUIC_MTU_OVERHEAD, TLS_ALPN_PROTOCOLS, TLS_INITIAL_CIPHER_SUITE, TLS_PROTOCOL_VERSIONS,
};
use crate::error::{ConfigError, NoiseError, Result};
use base64::prelude::*;
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use ipnet::IpNet;
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    EndpointConfig, TransportConfig,
};
use reishi_quinn::{
    noise_handshake_token_key, noise_hmac_key, KeyPair, NoiseConfigBuilder, PqKeyPair,
    PqNoiseConfigBuilder, PqPublicKey, PublicKey, REISHI_PQ_V1_QUIC_V1, REISHI_V1_QUIC_V1,
};
use rustls::crypto::aws_lc_rs::kx_group::{MLKEM768, X25519MLKEM768};
use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::{CipherSuite, RootCertStore};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Quincy server configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerConfig {
    /// The name of the tunnel
    pub name: String,
    /// Optional interface name to request for the tunnel device
    pub interface_name: Option<String>,
    /// The address to bind the tunnel to (default = 0.0.0.0)
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,
    /// The port to bind the tunnel to (default = 55555)
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    /// Whether to reuse the socket (default = false)
    ///
    /// This is useful when running multiple Quincy instances on the same port for load balancing.
    ///
    /// Unsupported on Windows.
    #[serde(default = "default_false_fn")]
    pub reuse_socket: bool,
    /// The network address of this tunnel (address + mask)
    pub tunnel_network: IpNet,
    /// Whether to isolate clients from each other (default = true)
    #[serde(default = "default_true_fn")]
    pub isolate_clients: bool,
    /// Authentication configuration
    pub authentication: ServerAuthenticationConfig,
    /// Miscellaneous connection configuration
    #[serde(default)]
    pub connection: ConnectionConfig,
    /// Protocol configuration (TLS or Noise)
    #[serde(default)]
    pub protocol: ServerProtocolConfig,
    /// Logging configuration
    pub log: LogConfig,
}

/// Server protocol configuration.
///
/// Selects between TLS and Noise as the cryptographic protocol for QUIC.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum ServerProtocolConfig {
    /// TLS 1.3 protocol mode (default)
    Tls(ServerTlsConfig),
    /// Noise IK protocol mode
    Noise(ServerNoiseConfig),
}

/// Server TLS protocol configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerTlsConfig {
    /// The key exchange algorithm to use (default = Hybrid)
    #[serde(default = "default_tls_key_exchange")]
    pub key_exchange: TlsKeyExchange,
    /// The certificate to use for the tunnel
    pub certificate_file: PathBuf,
    /// The certificate private key to use for the tunnel
    pub certificate_key_file: PathBuf,
}

/// Server Noise protocol configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerNoiseConfig {
    /// The key exchange algorithm to use (default = Standard)
    #[serde(default = "default_noise_key_exchange")]
    pub key_exchange: NoiseKeyExchange,
    /// Base64-encoded server private key (32 bytes for Standard, 96 bytes for Hybrid)
    pub private_key: String,
}

/// Quincy server-side authentication configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerAuthenticationConfig {
    /// The type of authenticator to use (default = users_file)
    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,
    /// The path to the file containing the list of users and their password hashes
    pub users_file: PathBuf,
}

/// Quincy client configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientConfig {
    /// Connection string to be used to connect to a Quincy server
    pub connection_string: String,
    /// Authentication configuration
    pub authentication: ClientAuthenticationConfig,
    /// QUIC connection configuration
    #[serde(default)]
    pub connection: ConnectionConfig,
    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,
    /// Protocol configuration (TLS or Noise)
    #[serde(default)]
    pub protocol: ClientProtocolConfig,
    /// Logging configuration
    pub log: LogConfig,
}

/// Client protocol configuration.
///
/// Selects between TLS and Noise as the cryptographic protocol for QUIC.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum ClientProtocolConfig {
    /// TLS 1.3 protocol mode (default)
    Tls(ClientTlsConfig),
    /// Noise IK protocol mode
    Noise(ClientNoiseConfig),
}

/// Client TLS protocol configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientTlsConfig {
    /// The key exchange algorithm to use (default = Hybrid)
    #[serde(default = "default_tls_key_exchange")]
    pub key_exchange: TlsKeyExchange,
    /// A list of trusted certificate file paths
    #[serde(default)]
    pub trusted_certificate_paths: Vec<PathBuf>,
    /// A list of trusted certificates as PEM strings
    #[serde(default)]
    pub trusted_certificates: Vec<String>,
}

/// Client Noise protocol configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientNoiseConfig {
    /// The key exchange algorithm to use (default = Standard)
    #[serde(default = "default_noise_key_exchange")]
    pub key_exchange: NoiseKeyExchange,
    /// Base64-encoded server public key (32 bytes for Standard, 1216 bytes for Hybrid)
    pub server_public_key: String,
}

/// Quincy client-side authentication configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientAuthenticationConfig {
    /// The type of authenticator to use (default = users_file)
    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,
    /// The username to use for authentication
    pub username: String,
    /// The password to use for authentication
    pub password: String,
}

/// TLS key exchange algorithm.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub enum TlsKeyExchange {
    /// ECDH (X25519)
    #[serde(alias = "standard")]
    Standard,
    /// X25519 + ML-KEM-768
    #[serde(alias = "hybrid")]
    Hybrid,
    /// ML-KEM-768
    #[serde(alias = "post_quantum")]
    PostQuantum,
}

/// Noise key exchange algorithm.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub enum NoiseKeyExchange {
    /// X25519 Diffie-Hellman
    #[serde(alias = "standard")]
    Standard,
    /// X25519 + ML-KEM-768 hybrid
    #[serde(alias = "hybrid")]
    Hybrid,
}

/// QUIC connection configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ConnectionConfig {
    /// The MTU to use for connections and the TUN interface (default = 1400)
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// The congestion control algorithm to use (default = Cubic)
    #[serde(default = "default_congestion_controller")]
    pub congestion_controller: CongestionController,
    /// The time after which a connection is considered timed out in seconds (default = 30)
    #[serde(default = "default_timeout_s")]
    pub connection_timeout_s: u64,
    /// Keep alive interval for connections in seconds (default = 25)
    #[serde(default = "default_keep_alive_interval_s")]
    pub keep_alive_interval_s: u64,
    /// The size of the send buffer of the socket and Quinn endpoint (default = 2097152)
    #[serde(default = "default_buffer_size")]
    pub send_buffer_size: u64,
    /// The size of the receive buffer of the socket and Quinn endpoint (default = 2097152)
    #[serde(default = "default_buffer_size")]
    pub recv_buffer_size: u64,
}

/// Network configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct NetworkConfig {
    /// Routes/networks to be routed through the tunnel
    ///
    /// In the format of `address/mask`, e.g.:
    /// ```toml
    /// routes = [
    ///     "10.0.1.0/24",
    ///     "10.11.12.0/24"
    /// ]
    /// ```
    #[serde(default = "default_routes")]
    pub routes: Vec<IpNet>,
    /// DNS servers to use for the tunnel
    ///
    /// In the format of `address`, e.g.:
    /// ```toml
    /// dns_servers = [
    ///     "10.0.1.1",
    /// ]
    /// ```
    #[serde(default = "default_dns_servers")]
    pub dns_servers: Vec<IpAddr>,
    /// Optional interface name to request for the tunnel device
    pub interface_name: Option<String>,
}

/// Logging configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct LogConfig {
    /// The log level to use (default = info)
    #[serde(default = "default_log_level")]
    pub level: String,
}

/// Authentication type.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub enum AuthType {
    /// File-based user authentication with username/password
    #[serde(alias = "users_file")]
    UsersFile,
}

/// Congestion control algorithm to use for QUIC connections.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub enum CongestionController {
    /// CUBIC congestion control (RFC 8312) - widely deployed, loss-based
    #[serde(alias = "cubic")]
    Cubic,
    /// BBR congestion control - latency-based, experimental in Quinn
    #[serde(alias = "bbr", alias = "BBR")]
    Bbr,
    /// New Reno congestion control - simple, traditional TCP-style
    #[serde(alias = "new_reno")]
    NewReno,
}

pub trait ConfigInit<T: DeserializeOwned> {
    /// Initializes the configuration object from the given Figment.
    ///
    /// ### Arguments
    /// - `figment` - the Figment to use for initialization
    fn init(figment: Figment, _env_prefix: &str) -> Result<T> {
        Ok(figment.extract()?)
    }
}

pub trait FromPath<T: DeserializeOwned + ConfigInit<T>> {
    /// Creates a configuration object from the given path and ENV prefix.
    ///
    /// ### Arguments
    /// - `path` - a path to the configuration file
    /// - `env_prefix` - the ENV prefix to use for overrides
    fn from_path(path: &Path, env_prefix: &str) -> Result<T> {
        if !path.exists() {
            return Err(ConfigError::FileNotFound {
                path: path.to_path_buf(),
            }
            .into());
        }

        let figment = Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed(env_prefix).split("__"));

        T::init(figment, env_prefix)
    }
}

impl ConfigInit<ServerConfig> for ServerConfig {}
impl ConfigInit<ClientConfig> for ClientConfig {}

impl FromPath<ServerConfig> for ServerConfig {}
impl FromPath<ClientConfig> for ClientConfig {}

impl Default for ServerProtocolConfig {
    fn default() -> Self {
        Self::Tls(ServerTlsConfig {
            key_exchange: default_tls_key_exchange(),
            certificate_file: PathBuf::new(),
            certificate_key_file: PathBuf::new(),
        })
    }
}

impl Default for ClientProtocolConfig {
    fn default() -> Self {
        Self::Tls(ClientTlsConfig {
            key_exchange: default_tls_key_exchange(),
            trusted_certificate_paths: Vec::new(),
            trusted_certificates: Vec::new(),
        })
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            mtu: default_mtu(),
            congestion_controller: default_congestion_controller(),
            connection_timeout_s: default_timeout_s(),
            keep_alive_interval_s: default_keep_alive_interval_s(),
            send_buffer_size: default_buffer_size(),
            recv_buffer_size: default_buffer_size(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            routes: default_routes(),
            dns_servers: default_dns_servers(),
            interface_name: None,
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_bind_address() -> IpAddr {
    "0.0.0.0".parse().expect("Default address is valid")
}

fn default_bind_port() -> u16 {
    55555
}

fn default_buffer_size() -> u64 {
    2097152
}

fn default_mtu() -> u16 {
    1400
}

fn default_congestion_controller() -> CongestionController {
    CongestionController::Cubic
}

fn default_timeout_s() -> u64 {
    30
}

fn default_keep_alive_interval_s() -> u64 {
    25
}

fn default_auth_type() -> AuthType {
    AuthType::UsersFile
}

fn default_routes() -> Vec<IpNet> {
    Vec::new()
}

fn default_dns_servers() -> Vec<IpAddr> {
    Vec::new()
}

fn default_true_fn() -> bool {
    true
}

fn default_false_fn() -> bool {
    false
}

fn default_tls_key_exchange() -> TlsKeyExchange {
    TlsKeyExchange::Hybrid
}

fn default_noise_key_exchange() -> NoiseKeyExchange {
    NoiseKeyExchange::Standard
}

// --- TLS crypto provider ---

/// Builds a rustls CryptoProvider configured for the given TLS key exchange mode.
fn tls_crypto_provider(key_exchange: &TlsKeyExchange) -> CryptoProvider {
    let mut custom_provider = aws_lc_rs::default_provider();

    custom_provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            CipherSuite::TLS13_AES_256_GCM_SHA384 | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        )
    });

    match key_exchange {
        TlsKeyExchange::Standard => custom_provider,
        TlsKeyExchange::Hybrid => CryptoProvider {
            kx_groups: vec![X25519MLKEM768],
            ..custom_provider
        },
        TlsKeyExchange::PostQuantum => CryptoProvider {
            kx_groups: vec![MLKEM768],
            ..custom_provider
        },
    }
}

// --- Client config builders ---

impl ClientConfig {
    /// Creates Quinn client configuration from this Quincy client configuration.
    ///
    /// ### Returns
    /// - `quinn::ClientConfig` - the Quinn client configuration
    pub fn quinn_client_config(&self) -> Result<quinn::ClientConfig> {
        match &self.protocol {
            ClientProtocolConfig::Tls(tls) => self.build_tls_client_config(tls),
            ClientProtocolConfig::Noise(noise) => self.build_noise_client_config(noise),
        }
    }

    /// Builds a TLS-based Quinn client configuration.
    fn build_tls_client_config(&self, tls: &ClientTlsConfig) -> Result<quinn::ClientConfig> {
        let mut cert_store = RootCertStore::empty();

        for cert_path in &tls.trusted_certificate_paths {
            let certs = load_certificates_from_file(cert_path)?;
            cert_store.add_parsable_certificates(certs);
        }

        for pem_data in &tls.trusted_certificates {
            let certs = load_certificates_from_pem(pem_data)?;
            cert_store.add_parsable_certificates(certs);
        }

        let crypto_provider = Arc::from(tls_crypto_provider(&tls.key_exchange));

        let mut rustls_config = rustls::ClientConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
            .with_root_certificates(cert_store)
            .with_no_client_auth();

        rustls_config.alpn_protocols.clone_from(&TLS_ALPN_PROTOCOLS);

        let quic_client_config = QuicClientConfig::with_initial(
            rustls_config.into(),
            TLS_INITIAL_CIPHER_SUITE
                .tls13()
                .expect("QUIC initial suite is a valid TLS 1.3 suite")
                .quic_suite()
                .expect("QUIC initial suite is a valid QUIC suite"),
        )
        .map_err(|e| ConfigError::InvalidValue {
            field: "quic_client_config".to_string(),
            reason: format!("QUIC configuration creation failed: {e}"),
        })?;

        let transport_config = self.connection.as_transport_config(true)?;
        let mut quinn_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        quinn_config.transport_config(Arc::new(transport_config));

        Ok(quinn_config)
    }

    /// Builds a Noise IK-based Quinn client configuration.
    fn build_noise_client_config(&self, noise: &ClientNoiseConfig) -> Result<quinn::ClientConfig> {
        let mut quinn_config = match noise.key_exchange {
            NoiseKeyExchange::Standard => {
                let server_pub_bytes = decode_base64_key(&noise.server_public_key, 32)?;
                let server_public = PublicKey::from_bytes(
                    <[u8; 32]>::try_from(&server_pub_bytes[..])
                        .expect("key length already validated"),
                );

                let local_keypair = KeyPair::generate(&mut rand_core::OsRng);

                let client_config = NoiseConfigBuilder::new(local_keypair)
                    .with_remote_public(server_public)
                    .build_client_config()
                    .map_err(|e| NoiseError::ConfigError {
                        reason: format!("Failed to build Noise client config: {e}"),
                    })?;

                let mut cfg = quinn::ClientConfig::new(Arc::new(client_config));
                cfg.version(REISHI_V1_QUIC_V1);
                cfg
            }
            NoiseKeyExchange::Hybrid => {
                let server_pub_bytes = decode_base64_key(&noise.server_public_key, 1216)?;
                let server_public =
                    PqPublicKey::from_bytes(&server_pub_bytes).ok_or(NoiseError::InvalidKey {
                        reason: "Invalid PQ public key material".to_string(),
                    })?;

                let local_keypair = PqKeyPair::generate(&mut rand_core::OsRng);

                let client_config = PqNoiseConfigBuilder::new(local_keypair)
                    .with_remote_public(server_public)
                    .build_client_config()
                    .map_err(|e| NoiseError::ConfigError {
                        reason: format!("Failed to build PQ Noise client config: {e}"),
                    })?;

                let mut cfg = quinn::ClientConfig::new(Arc::new(client_config));
                cfg.version(REISHI_PQ_V1_QUIC_V1);
                cfg
            }
        };

        let transport_config = self.connection.as_transport_config(true)?;
        quinn_config.transport_config(Arc::new(transport_config));

        Ok(quinn_config)
    }

    /// Returns the Noise key exchange mode if the protocol is Noise, or `None` for TLS.
    pub fn noise_key_exchange(&self) -> Option<&NoiseKeyExchange> {
        match &self.protocol {
            ClientProtocolConfig::Noise(noise) => Some(&noise.key_exchange),
            ClientProtocolConfig::Tls(_) => None,
        }
    }
}

// --- Server config builders ---

impl ServerConfig {
    /// Creates Quinn server configuration from this Quincy tunnel configuration.
    ///
    /// ### Returns
    /// - `quinn::ServerConfig` - the Quinn server configuration
    pub fn as_quinn_server_config(&self) -> Result<quinn::ServerConfig> {
        match &self.protocol {
            ServerProtocolConfig::Tls(tls) => self.build_tls_server_config(tls),
            ServerProtocolConfig::Noise(noise) => self.build_noise_server_config(noise),
        }
    }

    /// Builds a TLS-based Quinn server configuration.
    fn build_tls_server_config(&self, tls: &ServerTlsConfig) -> Result<quinn::ServerConfig> {
        let key = load_private_key_from_file(&tls.certificate_key_file)?;
        let certs = load_certificates_from_file(&tls.certificate_file)?;

        let crypto_provider = Arc::from(tls_crypto_provider(&tls.key_exchange));

        let mut rustls_config = rustls::ServerConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        rustls_config.alpn_protocols.clone_from(&TLS_ALPN_PROTOCOLS);
        rustls_config.max_early_data_size = 0;

        let quic_server_config = QuicServerConfig::with_initial(
            rustls_config.into(),
            TLS_INITIAL_CIPHER_SUITE
                .tls13()
                .expect("QUIC initial suite is a valid TLS 1.3 suite")
                .quic_suite()
                .expect("QUIC initial suite is a valid QUIC suite"),
        )
        .map_err(|e| ConfigError::InvalidValue {
            field: "quic_server_config".to_string(),
            reason: format!("QUIC configuration creation failed: {e}"),
        })?;

        let transport_config = self.connection.as_transport_config(false)?;
        let mut quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        quinn_config.transport_config(Arc::new(transport_config));

        Ok(quinn_config)
    }

    /// Builds a Noise IK-based Quinn server configuration.
    fn build_noise_server_config(&self, noise: &ServerNoiseConfig) -> Result<quinn::ServerConfig> {
        let mut quinn_config = match noise.key_exchange {
            NoiseKeyExchange::Standard => {
                let secret_bytes = decode_base64_key(&noise.private_key, 32)?;
                let keypair = KeyPair::from_secret_bytes(
                    <[u8; 32]>::try_from(&secret_bytes[..]).expect("key length already validated"),
                );

                let server_config = NoiseConfigBuilder::new(keypair)
                    .build_server_config()
                    .map_err(|e| NoiseError::ConfigError {
                        reason: format!("Failed to build Noise server config: {e}"),
                    })?;

                let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(server_config));
                cfg.token_key(noise_handshake_token_key());
                cfg
            }
            NoiseKeyExchange::Hybrid => {
                let secret_bytes = decode_base64_key(&noise.private_key, 96)?;
                let keypair = PqKeyPair::from_secret_bytes(
                    <[u8; 96]>::try_from(&secret_bytes[..]).expect("key length already validated"),
                );

                let server_config = PqNoiseConfigBuilder::new(keypair)
                    .build_server_config()
                    .map_err(|e| NoiseError::ConfigError {
                        reason: format!("Failed to build PQ Noise server config: {e}"),
                    })?;

                let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(server_config));
                cfg.token_key(noise_handshake_token_key());
                cfg
            }
        };

        let transport_config = self.connection.as_transport_config(false)?;
        quinn_config.transport_config(Arc::new(transport_config));

        Ok(quinn_config)
    }

    /// Returns the Noise key exchange mode if the protocol is Noise, or `None` for TLS.
    pub fn noise_key_exchange(&self) -> Option<&NoiseKeyExchange> {
        match &self.protocol {
            ServerProtocolConfig::Noise(noise) => Some(&noise.key_exchange),
            ServerProtocolConfig::Tls(_) => None,
        }
    }
}

// --- Endpoint config ---

impl ConnectionConfig {
    /// Creates a Quinn endpoint configuration.
    ///
    /// For Noise protocol mode, the endpoint uses Noise-specific HMAC keys and
    /// custom QUIC version numbers. For TLS mode, the default Quinn endpoint
    /// configuration is used.
    ///
    /// ### Arguments
    /// - `noise_kx` - the Noise key exchange mode, or `None` for TLS
    pub fn as_endpoint_config(
        &self,
        noise_kx: Option<&NoiseKeyExchange>,
    ) -> Result<EndpointConfig> {
        let mut endpoint_config = match noise_kx {
            None => EndpointConfig::default(),
            Some(kx) => {
                let mut cfg = EndpointConfig::new(noise_hmac_key());
                let version = match kx {
                    NoiseKeyExchange::Standard => REISHI_V1_QUIC_V1,
                    NoiseKeyExchange::Hybrid => REISHI_PQ_V1_QUIC_V1,
                };
                cfg.supported_versions(vec![version]);
                cfg
            }
        };

        endpoint_config
            .max_udp_payload_size(self.mtu_with_overhead()?)
            .map_err(|e| ConfigError::InvalidValue {
                field: "mtu".to_string(),
                reason: format!("MTU configuration failed: {e}"),
            })?;

        Ok(endpoint_config)
    }

    /// Creates a Quinn transport configuration.
    ///
    /// ### Arguments
    /// - `set_keep_alive` - whether to enable keep-alive (typically true for clients)
    pub fn as_transport_config(&self, set_keep_alive: bool) -> Result<TransportConfig> {
        let mut transport_config = TransportConfig::default();

        transport_config.max_idle_timeout(Some(
            Duration::from_secs(self.connection_timeout_s)
                .try_into()
                .map_err(|e| ConfigError::InvalidValue {
                    field: "connection_timeout_s".to_string(),
                    reason: format!("timeout value out of bounds: {e}"),
                })?,
        ));
        if set_keep_alive {
            transport_config
                .keep_alive_interval(Some(Duration::from_secs(self.keep_alive_interval_s)));
        }
        let mtu = self.mtu_with_overhead()?;
        transport_config.initial_mtu(mtu);
        transport_config.min_mtu(mtu);
        transport_config.congestion_controller_factory(self.congestion_controller_factory());

        Ok(transport_config)
    }

    /// Returns the MTU with QUIC overhead added.
    pub fn mtu_with_overhead(&self) -> Result<u16> {
        self.mtu.checked_add(QUIC_MTU_OVERHEAD).ok_or_else(|| {
            ConfigError::InvalidValue {
                field: "mtu".to_string(),
                reason: format!(
                    "MTU value {} overflows when adding QUIC overhead of {}",
                    self.mtu, QUIC_MTU_OVERHEAD
                ),
            }
            .into()
        })
    }

    /// Returns the congestion controller factory for this configuration.
    pub fn congestion_controller_factory(
        &self,
    ) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> {
        let config: Box<dyn quinn::congestion::ControllerFactory + Send + Sync> = match self
            .congestion_controller
        {
            CongestionController::Cubic => Box::new(quinn::congestion::CubicConfig::default()),
            CongestionController::Bbr => Box::new(quinn::congestion::BbrConfig::default()),
            CongestionController::NewReno => Box::new(quinn::congestion::NewRenoConfig::default()),
        };

        Arc::from(config)
    }
}

// --- Helpers ---

/// Decodes a base64-encoded key and validates its length.
fn decode_base64_key(encoded: &str, expected_len: usize) -> Result<Vec<u8>> {
    let bytes = BASE64_STANDARD
        .decode(encoded)
        .map_err(|e| NoiseError::InvalidKey {
            reason: format!("Invalid base64 encoding: {e}"),
        })?;

    if bytes.len() != expected_len {
        return Err(NoiseError::InvalidKey {
            reason: format!(
                "Expected {expected_len}-byte key, got {} bytes",
                bytes.len()
            ),
        }
        .into());
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::providers::{Format, Toml};

    #[test]
    fn parse_server_config_tls() {
        let toml = r#"
            name = "quincy-server"
            bind_address = "192.168.1.1"
            bind_port = 12345
            reuse_socket = true
            tunnel_network = "10.0.0.1/24"
            isolate_clients = false

            [protocol]
            mode = "tls"
            certificate_file = "/path/to/cert.pem"
            certificate_key_file = "/path/to/key.pem"
            key_exchange = "PostQuantum"

            [authentication]
            auth_type = "UsersFile"
            users_file = "/path/to/users"

            [connection]
            mtu = 1500
            congestion_controller = "Bbr"
            connection_timeout_s = 45
            keep_alive_interval_s = 20
            send_buffer_size = 4194304
            recv_buffer_size = 4194304

            [log]
            level = "debug"
        "#;

        let config: ServerConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("Failed to parse server config");

        assert_eq!(config.name, "quincy-server");
        assert_eq!(
            config.bind_address,
            "192.168.1.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(config.bind_port, 12345);
        assert!(config.reuse_socket);
        assert_eq!(
            config.tunnel_network,
            "10.0.0.1/24".parse::<IpNet>().unwrap()
        );
        assert!(!config.isolate_clients);
        assert_eq!(config.authentication.auth_type, AuthType::UsersFile);
        assert_eq!(
            config.authentication.users_file,
            PathBuf::from("/path/to/users")
        );
        assert_eq!(config.connection.mtu, 1500);
        assert_eq!(
            config.connection.congestion_controller,
            CongestionController::Bbr
        );
        assert_eq!(config.connection.connection_timeout_s, 45);
        assert_eq!(config.connection.keep_alive_interval_s, 20);
        assert_eq!(config.connection.send_buffer_size, 4194304);
        assert_eq!(config.connection.recv_buffer_size, 4194304);

        match &config.protocol {
            ServerProtocolConfig::Tls(tls) => {
                assert_eq!(tls.key_exchange, TlsKeyExchange::PostQuantum);
                assert_eq!(tls.certificate_file, PathBuf::from("/path/to/cert.pem"));
                assert_eq!(tls.certificate_key_file, PathBuf::from("/path/to/key.pem"));
            }
            _ => panic!("Expected TLS protocol config"),
        }

        assert_eq!(config.log.level, "debug");
    }

    #[test]
    fn parse_server_config_noise() {
        let toml = r#"
            name = "quincy-server"
            tunnel_network = "10.0.0.1/24"

            [protocol]
            mode = "noise"
            key_exchange = "Standard"
            private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

            [authentication]
            users_file = "/path/to/users"

            [log]
            level = "info"
        "#;

        let config: ServerConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("Failed to parse server config");

        match &config.protocol {
            ServerProtocolConfig::Noise(noise) => {
                assert_eq!(noise.key_exchange, NoiseKeyExchange::Standard);
                assert_eq!(
                    noise.private_key,
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                );
            }
            _ => panic!("Expected Noise protocol config"),
        }
    }

    #[test]
    fn parse_client_config_tls() {
        let toml = r#"
            connection_string = "example.com:55555"

            [authentication]
            auth_type = "UsersFile"
            username = "testuser"
            password = "testpass"

            [protocol]
            mode = "tls"
            key_exchange = "Standard"
            trusted_certificate_paths = ["/path/to/cert1.pem", "/path/to/cert2.pem"]
            trusted_certificates = ["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"]

            [connection]
            mtu = 1500
            congestion_controller = "NewReno"
            connection_timeout_s = 45
            keep_alive_interval_s = 20
            send_buffer_size = 1048576
            recv_buffer_size = 1048576

            [network]
            routes = ["10.0.1.0/24", "192.168.0.0/16"]
            dns_servers = ["8.8.8.8", "8.8.4.4"]

            [log]
            level = "trace"
        "#;

        let config: ClientConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("Failed to parse client config");

        assert_eq!(config.connection_string, "example.com:55555");
        assert_eq!(config.authentication.auth_type, AuthType::UsersFile);
        assert_eq!(config.authentication.username, "testuser");
        assert_eq!(config.authentication.password, "testpass");

        match &config.protocol {
            ClientProtocolConfig::Tls(tls) => {
                assert_eq!(tls.key_exchange, TlsKeyExchange::Standard);
                assert_eq!(
                    tls.trusted_certificate_paths,
                    vec![
                        PathBuf::from("/path/to/cert1.pem"),
                        PathBuf::from("/path/to/cert2.pem")
                    ]
                );
                assert_eq!(
                    tls.trusted_certificates,
                    vec!["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"]
                );
            }
            _ => panic!("Expected TLS protocol config"),
        }

        assert_eq!(config.connection.mtu, 1500);
        assert_eq!(
            config.connection.congestion_controller,
            CongestionController::NewReno
        );
        assert_eq!(config.connection.connection_timeout_s, 45);
        assert_eq!(config.connection.keep_alive_interval_s, 20);
        assert_eq!(config.connection.send_buffer_size, 1048576);
        assert_eq!(config.connection.recv_buffer_size, 1048576);
        assert_eq!(
            config.network.routes,
            vec![
                "10.0.1.0/24".parse::<IpNet>().unwrap(),
                "192.168.0.0/16".parse::<IpNet>().unwrap()
            ]
        );
        assert_eq!(
            config.network.dns_servers,
            vec![
                "8.8.8.8".parse::<IpAddr>().unwrap(),
                "8.8.4.4".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(config.log.level, "trace");
    }

    #[test]
    fn parse_client_config_noise() {
        let toml = r#"
            connection_string = "example.com:55555"

            [authentication]
            username = "testuser"
            password = "testpass"

            [protocol]
            mode = "noise"
            key_exchange = "Standard"
            server_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

            [log]
            level = "info"
        "#;

        let config: ClientConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("Failed to parse client config");

        match &config.protocol {
            ClientProtocolConfig::Noise(noise) => {
                assert_eq!(noise.key_exchange, NoiseKeyExchange::Standard);
                assert_eq!(
                    noise.server_public_key,
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                );
            }
            _ => panic!("Expected Noise protocol config"),
        }
    }

    #[test]
    fn decode_valid_base64_key() {
        let key_32 = BASE64_STANDARD.encode([0u8; 32]);
        assert!(decode_base64_key(&key_32, 32).is_ok());

        let key_96 = BASE64_STANDARD.encode([0u8; 96]);
        assert!(decode_base64_key(&key_96, 96).is_ok());
    }

    #[test]
    fn decode_base64_key_wrong_length() {
        let key_16 = BASE64_STANDARD.encode([0u8; 16]);
        let result = decode_base64_key(&key_16, 32);
        assert!(result.is_err());
    }

    #[test]
    fn decode_base64_key_invalid_encoding() {
        let result = decode_base64_key("not-valid-base64!!!", 32);
        assert!(result.is_err());
    }
}
