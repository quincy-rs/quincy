//! Client identity resolution after QUIC handshake.
//!
//! Extracts the peer identity from the completed connection and resolves it
//! to a username using the users file.

use std::any::Any;

use crate::users::UsersFile;
use ipnet::IpNet;
use quincy::config::ServerProtocolConfig;
use quincy::error::{AuthError, Result};
use quinn::Connection;
use reishi_quinn::{PeerIdentity, PublicKey};
use rustls::pki_types::CertificateDer;
use tracing::info;

use crate::server::address_pool::AddressPool;

/// Identifies the connected client and assigns them an IP address.
///
/// Extracts the peer identity from the QUIC connection (Noise public key or
/// TLS client certificate), looks up the corresponding username in the users
/// file, and allocates an IP address from the address pool.
///
/// ### Arguments
/// - `connection` - the established QUIC connection with completed handshake
/// - `protocol` - the server protocol configuration (TLS or Noise)
/// - `users` - the parsed users file for username lookup
/// - `address_pool` - the pool of available client IP addresses
///
/// ### Returns
/// A tuple of `(username, assigned_ip)` on success.
///
/// ### Errors
/// Returns `AuthError::HandshakeRejected` if the peer identity cannot be
/// extracted from the handshake, `AuthError::UserUnknown` if the peer is not
/// in the users file, or `AuthError::PermissionDenied` if the address pool
/// is exhausted.
pub async fn identify_and_assign(
    connection: &Connection,
    protocol: &ServerProtocolConfig,
    users: &UsersFile,
    address_pool: &AddressPool,
) -> Result<(String, IpNet)> {
    let username = identify_peer(connection, protocol, users)?;

    let client_address = address_pool
        .next_available_address()
        .ok_or(AuthError::PermissionDenied)?;

    info!(
        username = %username,
        address = %client_address,
        "Client identified and assigned IP"
    );

    Ok((username, client_address))
}

/// Extracts the peer identity from the connection and resolves the username.
///
/// For Noise connections, extracts the `PeerIdentity` and looks up the public
/// key in the users file. For TLS connections, extracts the client certificate
/// chain and looks up the fingerprint.
fn identify_peer(
    connection: &Connection,
    protocol: &ServerProtocolConfig,
    users: &UsersFile,
) -> Result<String> {
    let peer_identity = connection
        .peer_identity()
        .ok_or(AuthError::HandshakeRejected)?;

    match protocol {
        ServerProtocolConfig::Noise(_) => identify_noise_peer(peer_identity, users),
        ServerProtocolConfig::Tls(_) => identify_tls_peer(peer_identity, users),
    }
}

/// Resolves a Noise peer identity to a username.
///
/// Downcasts the peer identity to `PeerIdentity` and looks up the public key
/// (standard X25519 or hybrid PQ) in the users file.
fn identify_noise_peer(peer_identity: Box<dyn Any>, users: &UsersFile) -> Result<String> {
    let noise_identity = peer_identity
        .downcast_ref::<PeerIdentity>()
        .ok_or(AuthError::HandshakeRejected)?;

    // Try standard X25519 lookup first
    let pubkey = PublicKey::from_bytes(noise_identity.public_key);
    if let Some(username) = users.find_user_by_noise_pubkey(&pubkey) {
        return Ok(username.to_string());
    }

    // Try hybrid PQ lookup if a PQ public key is present
    if let Some(pq_pubkey) = &noise_identity.pq_public_key {
        if let Some(username) = users.find_user_by_noise_pq_pubkey(pq_pubkey) {
            return Ok(username.to_string());
        }
    }

    Err(AuthError::UserUnknown.into())
}

/// Resolves a TLS peer identity to a username.
///
/// Downcasts the peer identity to a certificate chain, computes the SHA-256
/// fingerprint of the end-entity certificate, and looks it up in the users file.
fn identify_tls_peer(peer_identity: Box<dyn Any>, users: &UsersFile) -> Result<String> {
    let certs = peer_identity
        .downcast_ref::<Vec<CertificateDer<'static>>>()
        .ok_or(AuthError::HandshakeRejected)?;

    let end_entity = certs.first().ok_or(AuthError::HandshakeRejected)?;

    let fingerprint = quincy::certificates::compute_cert_fingerprint(end_entity);

    users
        .find_user_by_cert_fingerprint(&fingerprint)
        .map(|s| s.to_string())
        .ok_or(AuthError::UserUnknown.into())
}
