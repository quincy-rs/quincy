use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use crate::certificates::{
    load_certificates_from_file, load_certificates_from_pem, load_private_key_from_file,
};
use crate::constants::{
    QUIC_MTU_OVERHEAD, TLS_ALPN_PROTOCOLS, TLS_INITIAL_CIPHER_SUITE, TLS_PROTOCOL_VERSIONS,
};
use crate::error::{ConfigError, NoiseError, Result};
use base64::{DecodeSliceError, prelude::*};
use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use ipnet::{IpAddrRange, IpNet, Ipv4AddrRange, Ipv6AddrRange};
use quinn::{
    EndpointConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use reishi_quinn::{
    KeyPair, NoiseConfigBuilder, PqKeyPair, PqNoiseConfigBuilder, PqPublicKey, PqStaticSecret,
    PublicKey, REISHI_PQ_V1_QUIC_V1, REISHI_V1_QUIC_V1, StaticSecret, noise_handshake_token_key,
    noise_hmac_key,
};
use rustls::crypto::aws_lc_rs::kx_group::{MLKEM768, X25519MLKEM768};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::{CipherSuite, RootCertStore};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Quincy server configuration.
#[derive(Clone, Debug, Deserialize)]
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
    /// Path to the TOML users file for authentication
    pub users_file: PathBuf,
    /// Whether to isolate clients from each other (default = true)
    #[serde(default = "default_true_fn")]
    pub isolate_clients: bool,
    /// Default bandwidth limit applied to users without a per-user limit.
    /// If not set, users without a per-user limit have unlimited bandwidth.
    #[serde(default)]
    pub default_bandwidth_limit: Option<Bandwidth>,
    /// Protocol configuration (TLS or Noise)
    pub protocol: ServerProtocolConfig,
    /// Miscellaneous connection configuration
    #[serde(default)]
    pub connection: ConnectionConfig,
    /// Logging configuration
    pub log: LogConfig,
    /// Prometheus metrics configuration.
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// Server protocol configuration.
///
/// Selects between TLS and Noise as the cryptographic protocol for QUIC.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum ServerProtocolConfig {
    /// TLS 1.3 protocol mode (default)
    Tls(ServerTlsConfig),
    /// Noise NK protocol mode
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
#[derive(Clone, Debug, Deserialize)]
pub struct ServerNoiseConfig {
    /// The key exchange algorithm to use (default = Standard)
    #[serde(default = "default_noise_key_exchange")]
    pub key_exchange: NoiseKeyExchange,
    /// Base64-encoded server private key (32 bytes for Standard, 96 bytes for Hybrid)
    pub private_key: SecretString,
}

/// Allowed Noise public keys for server-side client authentication.
///
/// Passed to the Noise config builder's `with_allowed_keys` to restrict
/// which clients can complete the handshake.
pub enum AllowedNoiseKeys {
    /// Standard X25519 public keys
    Standard(HashSet<PublicKey>),
    /// Hybrid X25519 + ML-KEM-768 public keys
    Hybrid(HashSet<PqPublicKey>),
}

/// Quincy client configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    /// Connection string to be used to connect to a Quincy server
    pub connection_string: String,
    /// Protocol configuration (TLS or Noise)
    pub protocol: ClientProtocolConfig,
    /// QUIC connection configuration
    #[serde(default)]
    pub connection: ConnectionConfig,
    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,
    /// Logging configuration
    pub log: LogConfig,
}

/// Client protocol configuration.
///
/// Selects between TLS and Noise as the cryptographic protocol for QUIC.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum ClientProtocolConfig {
    /// TLS 1.3 protocol mode (default)
    Tls(ClientTlsConfig),
    /// Noise NK protocol mode
    Noise(ClientNoiseConfig),
}

/// Client TLS protocol configuration.
#[derive(Clone, Debug, Deserialize)]
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
    /// Path to the client certificate file for mutual TLS authentication
    pub client_certificate_file: PathBuf,
    /// Path to the client certificate private key file
    pub client_certificate_key_file: PathBuf,
}

/// Client Noise protocol configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct ClientNoiseConfig {
    /// The key exchange algorithm to use (default = Standard)
    #[serde(default = "default_noise_key_exchange")]
    pub key_exchange: NoiseKeyExchange,
    /// Base64-encoded server public key (32 bytes for Standard, 1216 bytes for Hybrid)
    pub server_public_key: String,
    /// Base64-encoded client private key for persistent identity
    pub private_key: SecretString,
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

/// Prometheus metrics endpoint configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct MetricsConfig {
    /// Whether the metrics endpoint is enabled. Default: false.
    #[serde(default = "default_false_fn")]
    pub enabled: bool,
    /// Address to bind the metrics HTTP server. Default: 127.0.0.1 (loopback).
    #[serde(default = "default_metrics_address")]
    pub address: IpAddr,
    /// Port for the metrics HTTP server. Default: 9090.
    #[serde(default = "default_metrics_port")]
    pub port: u16,
    /// Interval in seconds between per-connection metrics reports. Default: 5.
    #[serde(default = "default_metrics_reporting_interval_s")]
    pub reporting_interval_s: u64,
    /// Idle timeout in seconds for per-connection metrics. Metrics that have
    /// not been updated within this duration are evicted from the registry on
    /// the next scrape. Set to 0 to disable eviction. Default: 300 (5 minutes).
    #[serde(default = "default_metrics_idle_timeout_s")]
    pub idle_timeout_s: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: default_metrics_address(),
            port: default_metrics_port(),
            reporting_interval_s: default_metrics_reporting_interval_s(),
            idle_timeout_s: default_metrics_idle_timeout_s(),
        }
    }
}

/// Bandwidth value stored as bytes per second.
///
/// Parsed from human-readable strings like "10 mbps", "500 kbps", "1 gbps".
/// Supported units (case-insensitive): bps, kbps, mbps, gbps.
/// The value is converted from bits/sec to bytes/sec during parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bandwidth(u64);

impl Bandwidth {
    /// Creates a new `Bandwidth` from a raw bytes-per-second value.
    pub const fn from_bytes_per_second(bytes_per_second: u64) -> Self {
        Self(bytes_per_second)
    }

    /// Returns the bandwidth in bytes per second.
    pub fn bytes_per_second(&self) -> u64 {
        self.0
    }

    /// Returns the bandwidth in kibibytes per second, with a minimum of 1.
    pub fn kib_per_second(&self) -> u32 {
        (self.0 / 1024).max(1) as u32
    }
}

impl fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits_per_second = self.0 * 8;

        if bits_per_second > 0 && bits_per_second % 1_000_000_000 == 0 {
            write!(f, "{} gbps", bits_per_second / 1_000_000_000)
        } else if bits_per_second > 0 && bits_per_second % 1_000_000 == 0 {
            write!(f, "{} mbps", bits_per_second / 1_000_000)
        } else if bits_per_second > 0 && bits_per_second % 1_000 == 0 {
            write!(f, "{} kbps", bits_per_second / 1_000)
        } else {
            write!(f, "{} bps", bits_per_second)
        }
    }
}

impl FromStr for Bandwidth {
    type Err = ConfigError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "bandwidth".to_string(),
                reason: "empty bandwidth value".to_string(),
            });
        }

        let split_pos = trimmed.find(|c: char| c.is_ascii_alphabetic());
        let split_pos = split_pos.ok_or_else(|| ConfigError::InvalidValue {
            field: "bandwidth".to_string(),
            reason: format!(
                "missing unit in bandwidth value '{trimmed}', expected bps/kbps/mbps/gbps"
            ),
        })?;

        let (num_part, unit_part) = trimmed.split_at(split_pos);
        let num_part = num_part.trim();
        let unit_part = unit_part.trim().to_ascii_lowercase();

        let value: f64 = num_part.parse().map_err(|_| ConfigError::InvalidValue {
            field: "bandwidth".to_string(),
            reason: format!("invalid numeric value '{num_part}'"),
        })?;

        if !value.is_finite() {
            return Err(ConfigError::InvalidValue {
                field: "bandwidth".to_string(),
                reason: "bandwidth must be a finite number".to_string(),
            });
        }

        if value < 0.0 {
            return Err(ConfigError::InvalidValue {
                field: "bandwidth".to_string(),
                reason: "bandwidth cannot be negative".to_string(),
            });
        }

        if value == 0.0 {
            return Err(ConfigError::InvalidValue {
                field: "bandwidth".to_string(),
                reason: "bandwidth cannot be zero".to_string(),
            });
        }

        let multiplier: f64 = match unit_part.as_str() {
            "bps" => 1.0,
            "kbps" => 1_000.0,
            "mbps" => 1_000_000.0,
            "gbps" => 1_000_000_000.0,
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: "bandwidth".to_string(),
                    reason: format!("unknown unit '{unit_part}', expected bps/kbps/mbps/gbps"),
                });
            }
        };

        let bits_per_second = value * multiplier;
        let bytes_per_second = (bits_per_second as u64) / 8;

        // Reject values that would overflow u32 when converted to KiB/s,
        // since the rate limiter operates with u32 token counts.
        let max_bytes_per_second = u32::MAX as u64 * 1024;
        if bytes_per_second > max_bytes_per_second {
            return Err(ConfigError::InvalidValue {
                field: "bandwidth".to_string(),
                reason: format!(
                    "bandwidth too large ({bytes_per_second} bytes/sec exceeds maximum of {max_bytes_per_second} bytes/sec)"
                ),
            });
        }

        Ok(Bandwidth(bytes_per_second))
    }
}

impl<'de> Deserialize<'de> for Bandwidth {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor};

        struct BandwidthVisitor;

        impl<'de> Visitor<'de> for BandwidthVisitor {
            type Value = Bandwidth;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a bandwidth string like \"10 mbps\", \"500 kbps\", \"1 gbps\"")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Bandwidth, E>
            where
                E: de::Error,
            {
                v.parse::<Bandwidth>().map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(BandwidthVisitor)
    }
}

/// A contiguous range of IP addresses, parsed from either a CIDR subnet
/// (e.g. `"10.0.0.100/30"`) or an explicit start–end range
/// (e.g. `"10.0.0.100 - 10.0.0.103"`).
///
/// Thin newtype around [`IpAddrRange`] that adds [`FromStr`] and
/// [`Deserialize`] support. Use [`Deref`] or [`into_inner()`](Self::into_inner)
/// to access the underlying `IpAddrRange`.
///
/// # Performance
///
/// Ranges are stored lazily and only expanded when iterated. However,
/// validation paths (overlap detection in [`UsersFile`](crate::config) and
/// containment checks in the address pool manager) iterate every address
/// eagerly. Very large ranges (e.g. a `/8` with 16 M addresses or any
/// wide IPv6 prefix) will cause proportional memory and CPU usage at
/// server startup. Keep per-user pool ranges small — a `/24` or narrower
/// is typical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddressRange(IpAddrRange);

impl AddressRange {
    /// Returns the underlying `IpAddrRange`.
    pub fn into_inner(self) -> IpAddrRange {
        self.0
    }
}

impl std::ops::Deref for AddressRange {
    type Target = IpAddrRange;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<IpAddrRange> for AddressRange {
    fn from(range: IpAddrRange) -> Self {
        Self(range)
    }
}

impl From<IpNet> for AddressRange {
    fn from(net: IpNet) -> Self {
        let range = match net {
            IpNet::V4(v4) => IpAddrRange::from(Ipv4AddrRange::new(v4.network(), v4.broadcast())),
            IpNet::V6(v6) => IpAddrRange::from(Ipv6AddrRange::new(v6.network(), v6.broadcast())),
        };
        Self(range)
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            IpAddrRange::V4(ref range) => {
                let (start, end) = (range.clone().next(), range.last());
                match (start, end) {
                    (Some(start), Some(end)) if start == end => write!(f, "{start}/32"),
                    (Some(start), Some(end)) => write!(f, "{start} - {end}"),
                    _ => write!(f, "<empty>"),
                }
            }
            IpAddrRange::V6(ref range) => {
                let (start, end) = (range.clone().next(), range.last());
                match (start, end) {
                    (Some(start), Some(end)) if start == end => write!(f, "{start}/128"),
                    (Some(start), Some(end)) => write!(f, "{start} - {end}"),
                    _ => write!(f, "<empty>"),
                }
            }
        }
    }
}

/// Returns an error if `addr` is a loopback or unspecified address, which are
/// never valid in a tunnel address pool.
fn reject_special_address(addr: IpAddr) -> std::result::Result<(), ConfigError> {
    if addr.is_loopback() {
        return Err(ConfigError::InvalidValue {
            field: "address_range".to_string(),
            reason: format!("loopback address {addr} is not allowed in an address range"),
        });
    }
    if addr.is_unspecified() {
        return Err(ConfigError::InvalidValue {
            field: "address_range".to_string(),
            reason: format!("unspecified address {addr} is not allowed in an address range"),
        });
    }
    Ok(())
}

impl FromStr for AddressRange {
    type Err = ConfigError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let trimmed = s.trim();

        // Try CIDR first (contains '/')
        if trimmed.contains('/') {
            let net: IpNet = trimmed.parse().map_err(|_| ConfigError::InvalidValue {
                field: "address_range".to_string(),
                reason: format!("invalid CIDR notation: '{trimmed}'"),
            })?;

            reject_special_address(net.network())?;
            reject_special_address(net.broadcast())?;

            return Ok(AddressRange::from(net));
        }

        // Try range format: "start - end"
        if let Some((left, right)) = trimmed.split_once('-') {
            let start: IpAddr = left.trim().parse().map_err(|_| ConfigError::InvalidValue {
                field: "address_range".to_string(),
                reason: format!("invalid start address in range: '{}'", left.trim()),
            })?;
            let end: IpAddr = right
                .trim()
                .parse()
                .map_err(|_| ConfigError::InvalidValue {
                    field: "address_range".to_string(),
                    reason: format!("invalid end address in range: '{}'", right.trim()),
                })?;

            reject_special_address(start)?;
            reject_special_address(end)?;

            let range = match (start, end) {
                (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
                    if start_v4 > end_v4 {
                        return Err(ConfigError::InvalidValue {
                            field: "address_range".to_string(),
                            reason: format!(
                                "range start ({start_v4}) must not be greater than end ({end_v4})"
                            ),
                        });
                    }
                    IpAddrRange::from(Ipv4AddrRange::new(start_v4, end_v4))
                }
                (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) => {
                    if start_v6 > end_v6 {
                        return Err(ConfigError::InvalidValue {
                            field: "address_range".to_string(),
                            reason: format!(
                                "range start ({start_v6}) must not be greater than end ({end_v6})"
                            ),
                        });
                    }
                    IpAddrRange::from(Ipv6AddrRange::new(start_v6, end_v6))
                }
                _ => {
                    return Err(ConfigError::InvalidValue {
                        field: "address_range".to_string(),
                        reason: format!(
                            "range start ({start}) and end ({end}) must be the same IP family"
                        ),
                    });
                }
            };

            return Ok(AddressRange(range));
        }

        Err(ConfigError::InvalidValue {
            field: "address_range".to_string(),
            reason: format!(
                "invalid address range '{trimmed}': expected CIDR (e.g. '10.0.0.0/30') \
                 or range (e.g. '10.0.0.1 - 10.0.0.5')"
            ),
        })
    }
}

impl<'de> Deserialize<'de> for AddressRange {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor};

        struct AddressRangeVisitor;

        impl<'de> Visitor<'de> for AddressRangeVisitor {
            type Value = AddressRange;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "an address range string like \"10.0.0.0/30\" or \"10.0.0.1 - 10.0.0.5\"",
                )
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<AddressRange, E>
            where
                E: de::Error,
            {
                v.parse::<AddressRange>().map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(AddressRangeVisitor)
    }
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

fn default_metrics_address() -> IpAddr {
    "127.0.0.1".parse().expect("Loopback address is valid")
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_metrics_reporting_interval_s() -> u64 {
    5
}

fn default_metrics_idle_timeout_s() -> u64 {
    300
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

    /// Builds a TLS-based Quinn client configuration with mutual authentication.
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

        let client_certs = load_certificates_from_file(&tls.client_certificate_file)?;
        let client_key = load_private_key_from_file(&tls.client_certificate_key_file)?;

        let crypto_provider = Arc::from(tls_crypto_provider(&tls.key_exchange));

        let mut rustls_config = rustls::ClientConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
            .with_root_certificates(cert_store)
            .with_client_auth_cert(client_certs, client_key)?;

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

    /// Builds a Noise IK-based Quinn client configuration using the client's persistent keypair.
    fn build_noise_client_config(&self, noise: &ClientNoiseConfig) -> Result<quinn::ClientConfig> {
        let mut quinn_config = match noise.key_exchange {
            NoiseKeyExchange::Standard => {
                let server_pub_bytes =
                    decode_base64_key::<{ PublicKey::LEN }>(&noise.server_public_key)?;
                let server_public = PublicKey::from_bytes(*server_pub_bytes);

                let secret_bytes =
                    decode_base64_key::<{ StaticSecret::LEN }>(noise.private_key.expose_secret())?;
                let local_keypair = KeyPair::from_secret_bytes(&secret_bytes);

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
                let server_pub_bytes =
                    decode_base64_key::<{ PqPublicKey::LEN }>(&noise.server_public_key)?;
                let server_public = PqPublicKey::from_bytes(*server_pub_bytes);

                let secret_bytes = decode_base64_key::<{ PqStaticSecret::LEN }>(
                    noise.private_key.expose_secret(),
                )?;
                let local_keypair = PqKeyPair::from_secret_bytes(&secret_bytes);

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
    /// ### Arguments
    /// - `allowed_keys` - for Noise mode, the set of allowed client public keys.
    ///   For TLS mode, pass `None`.
    /// - `allowed_fingerprints` - for TLS mode, the set of allowed client certificate
    ///   fingerprints. For Noise mode, pass `None`.
    ///
    /// ### Returns
    /// - `quinn::ServerConfig` - the Quinn server configuration
    pub fn as_quinn_server_config(
        &self,
        allowed_keys: Option<AllowedNoiseKeys>,
        allowed_fingerprints: Option<HashSet<String>>,
    ) -> Result<quinn::ServerConfig> {
        match &self.protocol {
            ServerProtocolConfig::Tls(tls) => {
                self.build_tls_server_config(tls, allowed_fingerprints.unwrap_or_default())
            }
            ServerProtocolConfig::Noise(noise) => {
                self.build_noise_server_config(noise, allowed_keys)
            }
        }
    }

    /// Builds a TLS-based Quinn server configuration with mutual authentication.
    ///
    /// ### Arguments
    /// - `tls` - the server TLS configuration
    /// - `allowed_fingerprints` - set of allowed client certificate fingerprints
    fn build_tls_server_config(
        &self,
        tls: &ServerTlsConfig,
        allowed_fingerprints: HashSet<String>,
    ) -> Result<quinn::ServerConfig> {
        let key = load_private_key_from_file(&tls.certificate_key_file)?;
        let certs = load_certificates_from_file(&tls.certificate_file)?;

        let crypto_provider = Arc::from(tls_crypto_provider(&tls.key_exchange));

        let verifier = Arc::new(crate::certificates::QuincyCertVerifier::new(
            allowed_fingerprints,
            &crypto_provider,
        ));

        let mut rustls_config = rustls::ServerConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
            .with_client_cert_verifier(verifier)
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

    /// Builds a Noise IK-based Quinn server configuration with allowed-keys restriction.
    ///
    /// ### Arguments
    /// - `noise` - the server Noise configuration
    /// - `allowed_keys` - optional set of allowed client public keys
    fn build_noise_server_config(
        &self,
        noise: &ServerNoiseConfig,
        allowed_keys: Option<AllowedNoiseKeys>,
    ) -> Result<quinn::ServerConfig> {
        let mut quinn_config = match noise.key_exchange {
            NoiseKeyExchange::Standard => {
                let secret_bytes =
                    decode_base64_key::<{ StaticSecret::LEN }>(noise.private_key.expose_secret())?;
                let keypair = KeyPair::from_secret_bytes(&secret_bytes);

                let mut builder = NoiseConfigBuilder::new(keypair);

                if let Some(AllowedNoiseKeys::Standard(keys)) = allowed_keys {
                    builder = builder.with_allowed_keys(keys);
                } else if allowed_keys.is_some() {
                    return Err(NoiseError::ConfigError {
                        reason: "Allowed keys use Hybrid mode, but server is configured for Standard Noise key exchange".to_string(),
                    }
                    .into());
                }

                let server_config =
                    builder
                        .build_server_config()
                        .map_err(|e| NoiseError::ConfigError {
                            reason: format!("Failed to build Noise server config: {e}"),
                        })?;

                let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(server_config));
                cfg.token_key(noise_handshake_token_key());
                cfg
            }
            NoiseKeyExchange::Hybrid => {
                let secret_bytes = decode_base64_key::<{ PqStaticSecret::LEN }>(
                    noise.private_key.expose_secret(),
                )?;
                let keypair = PqKeyPair::from_secret_bytes(&secret_bytes);

                let mut builder = PqNoiseConfigBuilder::new(keypair);

                if let Some(AllowedNoiseKeys::Hybrid(keys)) = allowed_keys {
                    builder = builder.with_allowed_keys(keys);
                } else if allowed_keys.is_some() {
                    return Err(NoiseError::ConfigError {
                        reason: "Allowed keys use Standard mode, but server is configured for Hybrid Noise key exchange".to_string(),
                    }
                    .into());
                }

                let server_config =
                    builder
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
pub fn decode_base64_key<const KEY_LEN: usize>(encoded: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);

    let decoded_bytes = BASE64_STANDARD
        .decode_slice(encoded.trim(), &mut *key_bytes)
        .map_err(|e| match e {
            DecodeSliceError::OutputSliceTooSmall => NoiseError::InvalidKey {
                reason: format!("Expected {KEY_LEN}-byte key"),
            },
            _ => NoiseError::InvalidKey {
                reason: "Invalid base64 encoding".to_string(),
            },
        })?;

    if decoded_bytes != KEY_LEN {
        return Err(NoiseError::InvalidKey {
            reason: format!("Expected {KEY_LEN}-byte key"),
        }
        .into());
    }

    Ok(key_bytes)
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
            users_file = "/path/to/users.toml"

            [protocol]
            mode = "tls"
            certificate_file = "/path/to/cert.pem"
            certificate_key_file = "/path/to/key.pem"
            key_exchange = "PostQuantum"

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
        assert_eq!(config.users_file, PathBuf::from("/path/to/users.toml"));
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
            users_file = "/path/to/users.toml"

            [protocol]
            mode = "noise"
            key_exchange = "Standard"
            private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

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
                    noise.private_key.expose_secret(),
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

            [protocol]
            mode = "tls"
            key_exchange = "Standard"
            trusted_certificate_paths = ["/path/to/cert1.pem", "/path/to/cert2.pem"]
            trusted_certificates = ["-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"]
            client_certificate_file = "/path/to/client_cert.pem"
            client_certificate_key_file = "/path/to/client_key.pem"

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
                assert_eq!(
                    tls.client_certificate_file,
                    PathBuf::from("/path/to/client_cert.pem")
                );
                assert_eq!(
                    tls.client_certificate_key_file,
                    PathBuf::from("/path/to/client_key.pem")
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

            [protocol]
            mode = "noise"
            key_exchange = "Standard"
            server_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            private_key = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

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
                assert_eq!(
                    noise.private_key.expose_secret(),
                    "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                );
            }
            _ => panic!("Expected Noise protocol config"),
        }
    }

    #[test]
    fn decode_valid_base64_key() {
        let key_32 = BASE64_STANDARD.encode([0u8; 32]);
        assert!(decode_base64_key::<32>(&key_32).is_ok());

        let key_96 = BASE64_STANDARD.encode([0u8; 96]);
        assert!(decode_base64_key::<96>(&key_96).is_ok());
    }

    #[test]
    fn decode_base64_key_wrong_length() {
        let key_16 = BASE64_STANDARD.encode([0u8; 16]);
        let result = decode_base64_key::<32>(&key_16);
        assert!(result.is_err());
    }

    #[test]
    fn decode_base64_key_invalid_encoding() {
        let result = decode_base64_key::<32>("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn parse_bandwidth_mbps() {
        assert_eq!(
            "10 mbps".parse::<Bandwidth>().unwrap(),
            Bandwidth(1_250_000)
        );
    }

    #[test]
    fn parse_bandwidth_kbps() {
        assert_eq!("500 kbps".parse::<Bandwidth>().unwrap(), Bandwidth(62_500));
    }

    #[test]
    fn parse_bandwidth_gbps() {
        assert_eq!(
            "1 gbps".parse::<Bandwidth>().unwrap(),
            Bandwidth(125_000_000)
        );
    }

    #[test]
    fn parse_bandwidth_bps() {
        assert_eq!("100 bps".parse::<Bandwidth>().unwrap(), Bandwidth(12));
    }

    #[test]
    fn parse_bandwidth_no_space() {
        assert_eq!("10mbps".parse::<Bandwidth>().unwrap(), Bandwidth(1_250_000));
    }

    #[test]
    fn parse_bandwidth_uppercase() {
        assert_eq!(
            "10 MBPS".parse::<Bandwidth>().unwrap(),
            Bandwidth(1_250_000)
        );
    }

    #[test]
    fn parse_bandwidth_rejects_invalid() {
        assert!("".parse::<Bandwidth>().is_err());
        assert!("abc".parse::<Bandwidth>().is_err());
        assert!("10".parse::<Bandwidth>().is_err());
        assert!("10 xyz".parse::<Bandwidth>().is_err());
        assert!("-5 mbps".parse::<Bandwidth>().is_err());
    }

    #[test]
    fn parse_bandwidth_rejects_oversized_value() {
        // 35184372088832 bps = 2^32 KiB/s, which overflows u32 in kib_per_second()
        assert!("35184372088832 bps".parse::<Bandwidth>().is_err());
        // Just under the limit should still succeed
        assert!("100 gbps".parse::<Bandwidth>().is_ok());
    }

    #[test]
    fn bandwidth_display_roundtrip() {
        assert_eq!(Bandwidth(1_250_000).to_string(), "10 mbps");
    }

    #[test]
    fn bandwidth_kib_per_second() {
        assert_eq!(Bandwidth(1_250_000).kib_per_second(), 1220);
    }

    #[test]
    fn bandwidth_kib_per_second_minimum() {
        assert_eq!(Bandwidth(100).kib_per_second(), 1);
    }

    #[test]
    fn parse_server_config_with_metrics_and_bandwidth() {
        let toml = r#"
            name = "quincy-server"
            tunnel_network = "10.0.0.1/24"
            users_file = "/path/to/users.toml"
            default_bandwidth_limit = "50 mbps"

            [protocol]
            mode = "noise"
            key_exchange = "Standard"
            private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

            [metrics]
            enabled = true
            address = "0.0.0.0"
            port = 9100
            idle_timeout_s = 120

            [log]
            level = "info"
        "#;

        let config: ServerConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("Failed to parse server config");

        assert!(config.metrics.enabled);
        assert_eq!(config.metrics.address, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(config.metrics.port, 9100);
        assert_eq!(config.metrics.idle_timeout_s, 120);
        assert_eq!(
            config.default_bandwidth_limit,
            Some(Bandwidth::from_bytes_per_second(6_250_000))
        );
    }

    #[test]
    fn metrics_idle_timeout_defaults_to_300() {
        let toml = r#"
            name = "quincy-server"
            tunnel_network = "10.0.0.1/24"
            users_file = "/path/to/users.toml"

            [protocol]
            mode = "noise"
            key_exchange = "Standard"
            private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

            [metrics]
            enabled = true

            [log]
            level = "info"
        "#;

        let config: ServerConfig = Figment::new()
            .merge(Toml::string(toml))
            .extract()
            .expect("Failed to parse server config");

        assert_eq!(config.metrics.idle_timeout_s, 300);
    }

    // --- AddressRange tests ---

    #[test]
    fn parse_address_range_cidr_v4() {
        let range: AddressRange = "10.0.0.0/30".parse().unwrap();
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0], "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(addrs[3], "10.0.0.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_address_range_cidr_single() {
        let range: AddressRange = "10.0.0.5/32".parse().unwrap();
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "10.0.0.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_address_range_explicit_with_spaces() {
        let range: AddressRange = "10.0.0.1 - 10.0.0.3".parse().unwrap();
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        assert_eq!(addrs.len(), 3);
    }

    #[test]
    fn parse_address_range_explicit_no_spaces() {
        let range: AddressRange = "10.0.0.1-10.0.0.3".parse().unwrap();
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        assert_eq!(addrs.len(), 3);
    }

    #[test]
    fn parse_address_range_single_ip_range() {
        let range: AddressRange = "10.0.0.5-10.0.0.5".parse().unwrap();
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn parse_address_range_rejects_start_greater_than_end() {
        let result = "10.0.0.5 - 10.0.0.1".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must not be greater than end"), "error: {err}");
    }

    #[test]
    fn parse_address_range_rejects_mixed_families() {
        let result = "10.0.0.1 - fd00::1".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("same IP family"), "error: {err}");
    }

    #[test]
    fn parse_address_range_rejects_invalid_cidr() {
        let result = "10.0.0.0/33".parse::<AddressRange>();
        assert!(result.is_err());
    }

    #[test]
    fn parse_address_range_rejects_garbage() {
        let result = "not-an-address".parse::<AddressRange>();
        assert!(result.is_err());
    }

    #[test]
    fn address_range_display_range() {
        let range: AddressRange = "10.0.0.1 - 10.0.0.3".parse().unwrap();
        assert_eq!(range.to_string(), "10.0.0.1 - 10.0.0.3");
    }

    #[test]
    fn address_range_display_single() {
        let range: AddressRange = "10.0.0.5/32".parse().unwrap();
        assert_eq!(range.to_string(), "10.0.0.5/32");
    }

    #[test]
    fn address_range_serde_roundtrip() {
        let range: AddressRange = "10.0.0.1 - 10.0.0.3".parse().unwrap();
        let toml = format!(
            r#"
            [users.alice]
            pool = ["{range}"]
        "#
        );

        #[derive(Deserialize)]
        struct Wrapper {
            users: std::collections::HashMap<String, PoolEntry>,
        }

        #[derive(Deserialize)]
        struct PoolEntry {
            pool: Vec<AddressRange>,
        }

        let wrapper: Wrapper = Figment::new()
            .merge(Toml::string(&toml))
            .extract()
            .expect("deserialization failed");

        assert_eq!(wrapper.users["alice"].pool[0], range);
    }

    #[test]
    fn parse_address_range_rejects_loopback_cidr() {
        let result = "127.0.0.0/8".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("loopback"), "error: {err}");
    }

    #[test]
    fn parse_address_range_rejects_loopback_range() {
        let result = "127.0.0.1 - 127.0.0.5".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("loopback"), "error: {err}");
    }

    #[test]
    fn parse_address_range_rejects_unspecified_cidr() {
        let result = "0.0.0.0/24".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unspecified"), "error: {err}");
    }

    #[test]
    fn parse_address_range_rejects_unspecified_range() {
        let result = "0.0.0.0 - 0.0.0.5".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unspecified"), "error: {err}");
    }

    #[test]
    fn parse_address_range_rejects_v6_loopback() {
        let result = "::1/128".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("loopback"), "error: {err}");
    }

    #[test]
    fn parse_address_range_rejects_v6_unspecified() {
        let result = "::/128".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unspecified"), "error: {err}");
    }

    #[test]
    fn parse_address_range_v6_cidr() {
        let range: AddressRange = "fd00::/126".parse().unwrap();
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0], "fd00::".parse::<IpAddr>().unwrap());
        assert_eq!(addrs[3], "fd00::3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_address_range_v6_cidr_single() {
        let range: AddressRange = "fd00::5/128".parse().unwrap();
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "fd00::5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_address_range_v6_range() {
        let range: AddressRange = "fd00::1 - fd00::3".parse().unwrap();
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], "fd00::1".parse::<IpAddr>().unwrap());
        assert_eq!(addrs[2], "fd00::3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_address_range_v6_single_ip_range() {
        let range: AddressRange = "fd00::a - fd00::a".parse().unwrap();
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn parse_address_range_v6_rejects_start_greater_than_end() {
        let result = "fd00::5 - fd00::1".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must not be greater than end"), "error: {err}");
    }

    #[test]
    fn parse_address_range_v6_rejects_loopback_range() {
        let result = "::1 - ::1".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("loopback"), "error: {err}");
    }

    #[test]
    fn parse_address_range_v6_rejects_unspecified_range() {
        let result = ":: - ::".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unspecified"), "error: {err}");
    }

    #[test]
    fn address_range_display_v6_range() {
        let range: AddressRange = "fd00::1 - fd00::3".parse().unwrap();
        assert_eq!(range.to_string(), "fd00::1 - fd00::3");
    }

    #[test]
    fn address_range_display_v6_single() {
        let range: AddressRange = "fd00::5/128".parse().unwrap();
        assert_eq!(range.to_string(), "fd00::5/128");
    }

    #[test]
    fn address_range_from_ipnet_v6() {
        let net: IpNet = "fd00::1/126".parse().unwrap();
        let range = AddressRange::from(net);
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        // /126 = 4 addresses: fd00::0 through fd00::3
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0], "fd00::".parse::<IpAddr>().unwrap());
        assert_eq!(addrs[3], "fd00::3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn address_range_v6_range_no_spaces() {
        let range: AddressRange = "fd00::1-fd00::3".parse().unwrap();
        let addrs: Vec<IpAddr> = range.into_inner().collect();
        assert_eq!(addrs.len(), 3);
    }

    #[test]
    fn address_range_v6_rejects_mixed_families() {
        let result = "fd00::1 - 10.0.0.1".parse::<AddressRange>();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("same IP family"), "error: {err}");
    }

    #[test]
    fn address_range_v6_serde_roundtrip() {
        let range: AddressRange = "fd00::1 - fd00::3".parse().unwrap();
        let toml = format!(
            r#"
            [users.alice]
            pool = ["{range}"]
        "#
        );

        #[derive(Deserialize)]
        struct Wrapper {
            users: std::collections::HashMap<String, PoolEntry>,
        }

        #[derive(Deserialize)]
        struct PoolEntry {
            pool: Vec<AddressRange>,
        }

        let wrapper: Wrapper = Figment::new()
            .merge(Toml::string(&toml))
            .extract()
            .expect("deserialization failed");

        assert_eq!(wrapper.users["alice"].pool[0], range);
    }
}
