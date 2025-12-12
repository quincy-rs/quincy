use std::sync::{Arc, LazyLock};

use quinn::Runtime;
use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;
use rustls::SupportedCipherSuite;

/// Represents the maximum MTU overhead for QUIC, since the QUIC header is variable in size.
pub const QUIC_MTU_OVERHEAD: u16 = 50;

/// Buffer size for authentication messages.
pub const AUTH_MESSAGE_BUFFER_SIZE: usize = 1024;

/// Packet buffer size for operations on the TUN interface.
pub const PACKET_BUFFER_SIZE: usize = 4;

/// Packet channel size used for communication between the TUN interface and QUIC tunnels.
pub const PACKET_CHANNEL_SIZE: usize = 1024 * 1024;

/// Represents the supported TLS protocol versions for Quincy.
pub static TLS_PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// Represents the supported TLS ALPN protocols for Quincy.
pub static TLS_ALPN_PROTOCOLS: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| vec![b"quincy".to_vec()]);

/// Represents the default cipher suite used for initial packets.
pub static TLS_INITIAL_CIPHER_SUITE: SupportedCipherSuite = TLS13_AES_128_GCM_SHA256;

/// Represents the async runtime used by Quinn.
pub static QUINN_RUNTIME: LazyLock<Arc<dyn Runtime>> =
    LazyLock::new(|| Arc::new(quinn::TokioRuntime));
