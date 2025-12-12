use crate::certificates::{
    load_certificates_from_file, load_certificates_from_pem, load_private_key_from_file,
};
use crate::constants::{
    QUIC_MTU_OVERHEAD, TLS_ALPN_PROTOCOLS, TLS_INITIAL_CIPHER_SUITE, TLS_PROTOCOL_VERSIONS,
};
use crate::error::{ConfigError, Result};
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use ipnet::IpNet;
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    EndpointConfig, TransportConfig,
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

/// Quincy server configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerConfig {
    /// The name of the tunnel
    pub name: String,
    /// The certificate to use for the tunnel
    pub certificate_file: PathBuf,
    /// The certificate private key to use for the tunnel
    pub certificate_key_file: PathBuf,
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
    /// Cryptography configuration
    #[serde(default)]
    pub crypto: CryptoConfig,
    /// Logging configuration
    pub log: LogConfig,
}

/// Quincy server-side authentication configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerAuthenticationConfig {
    /// The type of authenticator to use (default = users_file)
    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,
    /// The path to the file containing the list of users and their password hashes
    pub users_file: PathBuf,
}

/// Quincy client configuration
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
    /// Cryptography configuration
    #[serde(default)]
    pub crypto: CryptoConfig,
    /// Logging configuration
    pub log: LogConfig,
}

/// Quincy client-side authentication configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientAuthenticationConfig {
    /// The type of authenticator to use (default = users_file)
    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,
    /// The username to use for authentication
    pub username: String,
    /// The password to use for authentication
    pub password: String,
    /// A list of trusted certificate file paths
    #[serde(default = "default_trusted_certificate_paths")]
    pub trusted_certificate_paths: Vec<PathBuf>,
    /// A list of trusted certificates as PEM strings
    #[serde(default = "default_trusted_certificates")]
    pub trusted_certificates: Vec<String>,
}

/// QUIC connection configuration
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

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct CryptoConfig {
    /// The key exchange algorithm to use (default = Hybrid)
    #[serde(default = "default_key_exchange")]
    pub key_exchange: KeyExchange,
}

/// Network configuration
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
}

/// Logging configuration
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct LogConfig {
    /// The log level to use (default = info)
    #[serde(default = "default_log_level")]
    pub level: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub enum AuthType {
    /// File-based user authentication with username/password
    #[serde(alias = "users_file")]
    UsersFile,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub enum KeyExchange {
    /// ECDH
    #[serde(alias = "standard")]
    Standard,
    /// X25519 + MLKEM
    #[serde(alias = "hybrid")]
    Hybrid,
    /// MLKEM
    #[serde(alias = "post_quantum")]
    PostQuantum,
}

/// Congestion control algorithm to use for QUIC connections
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
    /// Initializes the configuration object from the given Figment
    ///
    /// ### Arguments
    /// - `figment` - the Figment to use for initialization
    fn init(figment: Figment, _env_prefix: &str) -> Result<T> {
        Ok(figment.extract()?)
    }
}

pub trait FromPath<T: DeserializeOwned + ConfigInit<T>> {
    /// Creates a configuration object from the given path and ENV prefix
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
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            key_exchange: default_key_exchange(),
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

fn default_trusted_certificate_paths() -> Vec<PathBuf> {
    Vec::new()
}

fn default_trusted_certificates() -> Vec<String> {
    Vec::new()
}

fn default_key_exchange() -> KeyExchange {
    KeyExchange::Hybrid
}

impl ClientConfig {
    /// Creates Quinn client configuration from this Quincy client configuration.
    ///
    /// ### Returns
    /// - `quinn::ClientConfig` - the Quinn client configuration
    pub fn quinn_client_config(&self) -> Result<quinn::ClientConfig> {
        let mut cert_store = RootCertStore::empty();

        // Load certificates from file paths
        for cert_path in &self.authentication.trusted_certificate_paths {
            let certs = load_certificates_from_file(cert_path)?;
            cert_store.add_parsable_certificates(certs);
        }

        // Load certificates from PEM strings
        for pem_data in &self.authentication.trusted_certificates {
            let certs = load_certificates_from_pem(pem_data)?;
            cert_store.add_parsable_certificates(certs);
        }

        let crypto_provider = Arc::from(self.crypto.crypto_provider());

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

        let mut quinn_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        let mut transport_config = TransportConfig::default();

        transport_config.max_idle_timeout(Some(
            Duration::from_secs(self.connection.connection_timeout_s)
                .try_into()
                .map_err(|e| ConfigError::InvalidValue {
                    field: "connection_timeout_s".to_string(),
                    reason: format!("timeout value out of bounds: {e}"),
                })?,
        ));
        transport_config.keep_alive_interval(Some(Duration::from_secs(
            self.connection.keep_alive_interval_s,
        )));
        transport_config.initial_mtu(self.connection.mtu_with_overhead());
        transport_config.min_mtu(self.connection.mtu_with_overhead());
        transport_config
            .congestion_controller_factory(self.connection.congestion_controller_factory());

        quinn_config.transport_config(Arc::new(transport_config));

        Ok(quinn_config)
    }
}

impl ServerConfig {
    /// Creates Quinn server configuration from this Quincy tunnel configuration.
    ///
    /// ### Arguments
    /// - `connection_config` - the connection configuration to use
    ///
    /// ### Returns
    /// - `quinn::ServerConfig` - the Quinn server configuration
    pub fn as_quinn_server_config(&self) -> Result<quinn::ServerConfig> {
        let certificate_file_path = self.certificate_file.clone();
        let certificate_key_path = self.certificate_key_file.clone();
        let key = load_private_key_from_file(&certificate_key_path)?;
        let certs = load_certificates_from_file(&certificate_file_path)?;

        let crypto_provider = Arc::from(self.crypto.crypto_provider());

        let mut rustls_config = rustls::ServerConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
            .with_no_client_auth()
            .with_single_cert(certs, key.into())?;

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

        let mut quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        let mut transport_config = TransportConfig::default();

        transport_config.max_idle_timeout(Some(
            Duration::from_secs(self.connection.connection_timeout_s)
                .try_into()
                .map_err(|e| ConfigError::InvalidValue {
                    field: "connection_timeout_s".to_string(),
                    reason: format!("timeout value out of bounds: {e}"),
                })?,
        ));
        transport_config.initial_mtu(self.connection.mtu_with_overhead());
        transport_config.min_mtu(self.connection.mtu_with_overhead());
        transport_config
            .congestion_controller_factory(self.connection.congestion_controller_factory());

        quinn_config.transport_config(Arc::new(transport_config));

        Ok(quinn_config)
    }
}

impl ConnectionConfig {
    pub fn as_endpoint_config(&self) -> Result<EndpointConfig> {
        let mut endpoint_config = EndpointConfig::default();
        endpoint_config
            .max_udp_payload_size(self.mtu_with_overhead())
            .map_err(|e| ConfigError::InvalidValue {
                field: "mtu".to_string(),
                reason: format!("MTU configuration failed: {e}"),
            })?;

        Ok(endpoint_config)
    }

    pub fn mtu_with_overhead(&self) -> u16 {
        self.mtu + QUIC_MTU_OVERHEAD
    }

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

impl CryptoConfig {
    fn crypto_provider(&self) -> CryptoProvider {
        let mut custom_provider = aws_lc_rs::default_provider();

        custom_provider.cipher_suites.retain(|suite| {
            matches!(
                suite.suite(),
                CipherSuite::TLS13_AES_256_GCM_SHA384 | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            )
        });

        match self.key_exchange {
            KeyExchange::Standard => custom_provider,
            KeyExchange::Hybrid => CryptoProvider {
                kx_groups: vec![X25519MLKEM768],
                ..custom_provider
            },
            KeyExchange::PostQuantum => CryptoProvider {
                kx_groups: vec![MLKEM768],
                ..custom_provider
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::providers::{Format, Toml};

    #[test]
    fn parse_server_config_full() {
        let toml = r#"
            name = "quincy-server"
            certificate_file = "/path/to/cert.pem"
            certificate_key_file = "/path/to/key.pem"
            bind_address = "192.168.1.1"
            bind_port = 12345
            reuse_socket = true
            tunnel_network = "10.0.0.1/24"
            isolate_clients = false

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

            [crypto]
            key_exchange = "PostQuantum"

            [log]
            level = "debug"
        "#;

        let config: ServerConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("Failed to parse server config");

        assert_eq!(config.name, "quincy-server");
        assert_eq!(config.certificate_file, PathBuf::from("/path/to/cert.pem"));
        assert_eq!(
            config.certificate_key_file,
            PathBuf::from("/path/to/key.pem")
        );
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
        assert_eq!(config.crypto.key_exchange, KeyExchange::PostQuantum);
        assert_eq!(config.log.level, "debug");
    }

    #[test]
    fn parse_client_config_full() {
        let toml = r#"
            connection_string = "example.com:55555"

            [authentication]
            auth_type = "UsersFile"
            username = "testuser"
            password = "testpass"
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

            [crypto]
            key_exchange = "Standard"

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
        assert_eq!(
            config.authentication.trusted_certificate_paths,
            vec![
                PathBuf::from("/path/to/cert1.pem"),
                PathBuf::from("/path/to/cert2.pem")
            ]
        );
        assert_eq!(
            config.authentication.trusted_certificates,
            vec!["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"]
        );
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
        assert_eq!(config.crypto.key_exchange, KeyExchange::Standard);
        assert_eq!(config.log.level, "trace");
    }
}
