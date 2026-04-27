//! Users file parser for Quincy VPN.
//!
//! Parses a TOML-formatted users file that maps usernames to their authorized
//! keys and certificates for handshake-layer authentication. Pre-builds
//! lookup indices for O(1) key and fingerprint resolution.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use figment::{
    Figment,
    providers::{Format, Toml},
};
use reishi_quinn::{PqPublicKey, PublicKey};
use serde::Deserialize;
use tracing::warn;

use quincy::config::{AddressRange, Bandwidth, decode_base64_key};
use quincy::error::{AuthError, Result};

/// A parsed users file mapping usernames to their authentication credentials.
///
/// Pre-builds internal lookup indices during construction so that key and
/// fingerprint lookups are O(1) rather than linear scans.
///
/// The TOML file has the following format:
/// ```toml
/// [users.alice]
/// authorized_keys = ["base64-encoded-x25519-pubkey"]
/// authorized_certs = ["sha256:hex-fingerprint"]
///
/// [users.bob]
/// authorized_keys = ["base64-encoded-pq-pubkey"]
/// ```
#[derive(Clone, Debug)]
pub struct UsersFile {
    /// Map of username to their authentication entry.
    pub users: HashMap<String, UserEntry>,
    /// Index: X25519 public key -> username.
    noise_key_to_user: HashMap<PublicKey, String>,
    /// Index: PQ public key -> username.
    noise_pq_key_to_user: HashMap<PqPublicKey, String>,
    /// Index: certificate fingerprint -> username.
    cert_fingerprint_to_user: HashMap<String, String>,
}

/// Raw deserialization target for the users file.
#[derive(Deserialize)]
struct RawUsersFile {
    #[serde(default)]
    users: HashMap<String, UserEntry>,
}

/// Authentication credentials for a single user.
#[derive(Clone, Debug, Deserialize)]
pub struct UserEntry {
    /// Base64-encoded public keys authorized for this user (Noise protocol).
    #[serde(default)]
    pub authorized_keys: Vec<String>,
    /// Certificate fingerprints authorized for this user (TLS mTLS).
    /// Format: `sha256:<hex>`
    #[serde(default)]
    pub authorized_certs: Vec<String>,
    /// Optional bandwidth limit for this user.
    /// Overrides the server's `default_bandwidth_limit`.
    /// Format: human-readable string, e.g. `"10 mbps"`.
    #[serde(default)]
    pub bandwidth_limit: Option<Bandwidth>,
    /// Optional per-user address pool. When set, this user can only receive
    /// tunnel IPs from these ranges, and the addresses are reserved (not
    /// available to other users).
    ///
    /// Keep ranges small (a `/24` or narrower is typical) — overlap validation
    /// iterates every address eagerly at startup.
    #[serde(default)]
    pub address_pool: Vec<AddressRange>,
}

impl UsersFile {
    /// Loads and parses a users file from the given path.
    ///
    /// ### Arguments
    /// - `path` - path to the TOML users file
    ///
    /// ### Errors
    /// Returns `AuthError::StoreUnavailable` if the file cannot be read or parsed,
    /// or `AuthError::InvalidUserStore` if the file contains duplicate keys/fingerprints
    /// or invalid fingerprint formats.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(AuthError::StoreUnavailable.into());
        }

        let figment = Figment::new().merge(Toml::file(path));
        let raw: RawUsersFile = figment.extract().map_err(|_| AuthError::StoreUnavailable)?;

        Self::from_raw(raw)
    }

    /// Parses a users file from a TOML string.
    ///
    /// ### Arguments
    /// - `content` - TOML content as a string
    ///
    /// ### Errors
    /// Returns `AuthError::StoreUnavailable` if the content cannot be parsed,
    /// or `AuthError::InvalidUserStore` if the content contains duplicate keys/fingerprints
    /// or invalid fingerprint formats.
    pub fn parse(content: &str) -> Result<Self> {
        let figment = Figment::new().merge(Toml::string(content));
        let raw: RawUsersFile = figment.extract().map_err(|_| AuthError::StoreUnavailable)?;

        Self::from_raw(raw)
    }

    /// Validates that a certificate fingerprint has the expected `sha256:<64 hex chars>` format.
    ///
    /// ### Arguments
    /// - `fingerprint` - the fingerprint string to validate
    /// - `username` - the username that owns this fingerprint (for error messages)
    ///
    /// ### Errors
    /// Returns `AuthError::InvalidUserStore` if the fingerprint format is invalid.
    fn validate_fingerprint(fingerprint: &str, username: &str) -> Result<()> {
        let Some(hex_part) = fingerprint.strip_prefix("sha256:") else {
            return Err(AuthError::InvalidUserStore {
                reason: format!(
                    "user '{username}': invalid fingerprint format '{fingerprint}' \
                     (must start with 'sha256:')"
                ),
            }
            .into());
        };

        if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AuthError::InvalidUserStore {
                reason: format!(
                    "user '{username}': invalid fingerprint format '{fingerprint}' \
                     (expected 'sha256:' followed by exactly 64 hex characters)"
                ),
            }
            .into());
        }

        Ok(())
    }

    /// Builds a `UsersFile` with pre-computed lookup indices from raw deserialized data.
    ///
    /// Validates fingerprint formats, normalizes fingerprints to lowercase, and
    /// checks for duplicate keys/fingerprints across users.
    ///
    /// ### Errors
    /// Returns `AuthError::InvalidUserStore` if duplicate keys or fingerprints are
    /// detected, or if a fingerprint has an invalid format.
    fn from_raw(raw: RawUsersFile) -> Result<Self> {
        let mut noise_key_to_user = HashMap::new();
        let mut noise_pq_key_to_user = HashMap::new();
        let mut cert_fingerprint_to_user = HashMap::new();

        for (username, entry) in &raw.users {
            for key_b64 in &entry.authorized_keys {
                let mut decoded = false;

                // Try as X25519 key (exactly 32 bytes)
                if let Ok(bytes) = decode_base64_key::<{ PublicKey::LEN }>(key_b64) {
                    let pubkey = PublicKey::from_bytes(*bytes);
                    if let Some(existing) = noise_key_to_user.get(&pubkey) {
                        return Err(AuthError::InvalidUserStore {
                            reason: format!(
                                "duplicate Noise X25519 key for users '{existing}' and '{username}'"
                            ),
                        }
                        .into());
                    }
                    noise_key_to_user.insert(pubkey, username.clone());
                    decoded = true;
                }

                // Try as PQ key (validated by from_bytes after length-checked decode)
                if let Ok(bytes) = decode_base64_key::<{ PqPublicKey::LEN }>(key_b64) {
                    let pq_pubkey = PqPublicKey::from_bytes(*bytes);
                    if let Some(existing) = noise_pq_key_to_user.get(&pq_pubkey) {
                        return Err(AuthError::InvalidUserStore {
                            reason: format!(
                                "duplicate Noise PQ key for users '{existing}' and '{username}'"
                            ),
                        }
                        .into());
                    }
                    noise_pq_key_to_user.insert(pq_pubkey, username.clone());
                    decoded = true;
                }

                if !decoded {
                    warn!(
                        "Ignoring unrecognized key for user '{username}': \
                         not a valid X25519 ({} bytes) or PQ ({} bytes) public key",
                        PublicKey::LEN,
                        PqPublicKey::LEN,
                    );
                }
            }

            for fp in &entry.authorized_certs {
                Self::validate_fingerprint(fp, username)?;

                let normalized = fp.to_lowercase();
                if let Some(existing) = cert_fingerprint_to_user.get(&normalized) {
                    return Err(AuthError::InvalidUserStore {
                        reason: format!(
                            "duplicate certificate fingerprint '{normalized}' \
                             for users '{existing}' and '{username}'"
                        ),
                    }
                    .into());
                }
                cert_fingerprint_to_user.insert(normalized, username.clone());
            }
        }

        // Validate per-user address pools: reject overlapping addresses between users
        let mut all_pool_addresses: HashMap<IpAddr, String> = HashMap::new();
        for (username, entry) in &raw.users {
            let mut user_addresses: HashSet<IpAddr> = HashSet::new();
            for range in &entry.address_pool {
                for addr in range.into_inner() {
                    if !user_addresses.insert(addr) {
                        return Err(AuthError::InvalidUserStore {
                            reason: format!(
                                "user '{username}': duplicate address {addr} in address_pool"
                            ),
                        }
                        .into());
                    }
                    if let Some(existing) = all_pool_addresses.get(&addr) {
                        return Err(AuthError::InvalidUserStore {
                            reason: format!(
                                "address {addr} claimed by both users '{existing}' and '{username}'"
                            ),
                        }
                        .into());
                    }
                    all_pool_addresses.insert(addr, username.clone());
                }
            }
        }

        Ok(Self {
            users: raw.users,
            noise_key_to_user,
            noise_pq_key_to_user,
            cert_fingerprint_to_user,
        })
    }

    /// Looks up a username by their Noise X25519 public key.
    ///
    /// ### Arguments
    /// - `pubkey` - the X25519 public key to search for
    ///
    /// ### Returns
    /// The username if found, or `None` if no user has this key authorized.
    pub fn find_user_by_noise_pubkey(&self, pubkey: &PublicKey) -> Option<&str> {
        self.noise_key_to_user.get(pubkey).map(|s| s.as_str())
    }

    /// Looks up a username by their Noise hybrid PQ public key.
    ///
    /// ### Arguments
    /// - `pq_pubkey` - the PQ public key to search for
    ///
    /// ### Returns
    /// The username if found, or `None` if no user has this key authorized.
    pub fn find_user_by_noise_pq_pubkey(&self, pq_pubkey: &PqPublicKey) -> Option<&str> {
        self.noise_pq_key_to_user.get(pq_pubkey).map(|s| s.as_str())
    }

    /// Looks up a username by a TLS certificate fingerprint.
    ///
    /// ### Arguments
    /// - `fingerprint` - the certificate fingerprint in `sha256:<hex>` format
    ///
    /// ### Returns
    /// The username if found, or `None` if no user has this fingerprint authorized.
    pub fn find_user_by_cert_fingerprint(&self, fingerprint: &str) -> Option<&str> {
        self.cert_fingerprint_to_user
            .get(&fingerprint.to_lowercase())
            .map(|s| s.as_str())
    }

    /// Collects all authorized X25519 public keys from all users.
    ///
    /// Keys that fail to decode (wrong length, invalid base64) are silently skipped.
    ///
    /// ### Returns
    /// A set of all valid X25519 public keys across all users.
    pub fn collect_noise_public_keys(&self) -> HashSet<PublicKey> {
        self.noise_key_to_user.keys().cloned().collect()
    }

    /// Collects all authorized hybrid PQ public keys from all users.
    ///
    /// ### Returns
    /// A set of all valid PQ public keys across all users.
    pub fn collect_noise_pq_public_keys(&self) -> HashSet<PqPublicKey> {
        self.noise_pq_key_to_user.keys().cloned().collect()
    }

    /// Collects all authorized certificate fingerprints from all users.
    ///
    /// ### Returns
    /// A set of all certificate fingerprints (in `sha256:<hex>` format) across all users.
    pub fn collect_cert_fingerprints(&self) -> HashSet<String> {
        self.cert_fingerprint_to_user.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_USERS_TOML: &str = r#"
        [users.alice]
        authorized_keys = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
        authorized_certs = ["sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"]
        bandwidth_limit = "10 mbps"

        [users.bob]
        authorized_keys = ["AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
        authorized_certs = []
    "#;

    #[test]
    fn parse_users_file() {
        let users = UsersFile::parse(SAMPLE_USERS_TOML).expect("valid TOML");
        assert_eq!(users.users.len(), 2);
        assert!(users.users.contains_key("alice"));
        assert!(users.users.contains_key("bob"));
    }

    #[test]
    fn parse_empty_users_file() {
        let users = UsersFile::parse("[users]").expect("valid TOML");
        assert!(users.users.is_empty());
    }

    #[test]
    fn parse_users_file_no_users_section() {
        let users = UsersFile::parse("").expect("valid TOML with defaults");
        assert!(users.users.is_empty());
    }

    #[test]
    fn find_user_by_noise_pubkey_found() {
        let users = UsersFile::parse(SAMPLE_USERS_TOML).expect("valid TOML");
        // "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" decodes to [0u8; 32]
        let key = PublicKey::from_bytes([0u8; 32]);
        assert_eq!(users.find_user_by_noise_pubkey(&key), Some("alice"));
    }

    #[test]
    fn find_user_by_noise_pubkey_not_found() {
        let users = UsersFile::parse(SAMPLE_USERS_TOML).expect("valid TOML");
        let key = PublicKey::from_bytes([0xFFu8; 32]);
        assert_eq!(users.find_user_by_noise_pubkey(&key), None);
    }

    #[test]
    fn find_user_by_cert_fingerprint_found() {
        let users = UsersFile::parse(SAMPLE_USERS_TOML).expect("valid TOML");
        assert_eq!(
            users.find_user_by_cert_fingerprint(
                "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            ),
            Some("alice")
        );
    }

    #[test]
    fn find_user_by_cert_fingerprint_not_found() {
        let users = UsersFile::parse(SAMPLE_USERS_TOML).expect("valid TOML");
        assert_eq!(
            users.find_user_by_cert_fingerprint("sha256:nonexistent"),
            None
        );
    }

    #[test]
    fn collect_noise_public_keys() {
        let users = UsersFile::parse(SAMPLE_USERS_TOML).expect("valid TOML");
        let keys = users.collect_noise_public_keys();
        // Both alice and bob have 32-byte keys
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn collect_cert_fingerprints() {
        let users = UsersFile::parse(SAMPLE_USERS_TOML).expect("valid TOML");
        let fps = users.collect_cert_fingerprints();
        assert_eq!(fps.len(), 1);
        assert!(
            fps.contains("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        );
    }

    #[test]
    fn user_entry_defaults() {
        let toml = r#"
            [users.charlie]
        "#;
        let users = UsersFile::parse(toml).expect("valid TOML");
        let charlie = users.users.get("charlie").expect("charlie exists");
        assert!(charlie.authorized_keys.is_empty());
        assert!(charlie.authorized_certs.is_empty());
    }

    #[test]
    fn load_nonexistent_file() {
        let result = UsersFile::load(Path::new("/nonexistent/users.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn indices_built_for_empty_users() {
        let users = UsersFile::parse("").expect("valid TOML");
        assert!(users.noise_key_to_user.is_empty());
        assert!(users.noise_pq_key_to_user.is_empty());
        assert!(users.cert_fingerprint_to_user.is_empty());
    }

    #[test]
    fn indices_built_correctly() {
        let users = UsersFile::parse(SAMPLE_USERS_TOML).expect("valid TOML");

        // Alice's key is [0u8; 32], Bob's key is [1, 0, 0, ..., 0]
        assert_eq!(users.noise_key_to_user.len(), 2);
        assert_eq!(users.cert_fingerprint_to_user.len(), 1);

        let alice_key = PublicKey::from_bytes([0u8; 32]);
        assert_eq!(users.noise_key_to_user.get(&alice_key).unwrap(), "alice");
        assert_eq!(
            users
                .cert_fingerprint_to_user
                .get("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
                .unwrap(),
            "alice"
        );
    }

    #[test]
    fn duplicate_noise_key_rejected() {
        // Both alice and bob share the same X25519 key ([0u8; 32])
        let toml = r#"
            [users.alice]
            authorized_keys = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]

            [users.bob]
            authorized_keys = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
        "#;
        let result = UsersFile::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("duplicate Noise X25519 key"), "error: {err}");
    }

    #[test]
    fn duplicate_cert_fingerprint_rejected() {
        let fp = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let toml = format!(
            r#"
            [users.alice]
            authorized_certs = ["{fp}"]

            [users.bob]
            authorized_certs = ["{fp}"]
        "#
        );
        let result = UsersFile::parse(&toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("duplicate certificate fingerprint"),
            "error: {err}"
        );
    }

    #[test]
    fn duplicate_cert_fingerprint_case_insensitive() {
        // Same fingerprint but with different casing should be detected as duplicate
        let toml = r#"
            [users.alice]
            authorized_certs = ["sha256:ABCDEF1234567890abcdef1234567890abcdef1234567890abcdef1234567890"]

            [users.bob]
            authorized_certs = ["sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"]
        "#;
        let result = UsersFile::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("duplicate certificate fingerprint"),
            "error: {err}"
        );
    }

    #[test]
    fn fingerprint_normalized_to_lowercase() {
        let toml = r#"
            [users.alice]
            authorized_certs = ["sha256:ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"]
        "#;
        let users = UsersFile::parse(toml).expect("valid TOML");
        // Lookup with lowercase should succeed after normalization
        assert_eq!(
            users.find_user_by_cert_fingerprint(
                "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            ),
            Some("alice")
        );
    }

    #[test]
    fn find_user_by_cert_fingerprint_mixed_case() {
        let toml = r#"
            [users.alice]
            authorized_certs = ["sha256:ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"]
        "#;
        let users = UsersFile::parse(toml).expect("valid TOML");
        // Lookup with lowercase should work
        assert_eq!(
            users.find_user_by_cert_fingerprint(
                "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            ),
            Some("alice")
        );
        // Lookup with mixed case should also work (defense in depth)
        assert_eq!(
            users.find_user_by_cert_fingerprint(
                "sha256:AbCdEf1234567890AbCdEf1234567890AbCdEf1234567890AbCdEf1234567890"
            ),
            Some("alice")
        );
    }

    #[test]
    fn fingerprint_missing_sha256_prefix_rejected() {
        let toml = r#"
            [users.alice]
            authorized_certs = ["abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"]
        "#;
        let result = UsersFile::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must start with 'sha256:'"), "error: {err}");
    }

    #[test]
    fn fingerprint_wrong_hex_length_rejected() {
        let toml = r#"
            [users.alice]
            authorized_certs = ["sha256:abcdef"]
        "#;
        let result = UsersFile::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exactly 64 hex characters"), "error: {err}");
    }

    #[test]
    fn fingerprint_non_hex_chars_rejected() {
        let toml = r#"
            [users.alice]
            authorized_certs = ["sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"]
        "#;
        let result = UsersFile::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exactly 64 hex characters"), "error: {err}");
    }

    #[test]
    fn fingerprint_valid_formats_accepted() {
        // All lowercase
        let toml = r#"
            [users.alice]
            authorized_certs = ["sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
        "#;
        assert!(UsersFile::parse(toml).is_ok());

        // Mixed case (should be normalized)
        let toml = r#"
            [users.alice]
            authorized_certs = ["sha256:0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef"]
        "#;
        assert!(UsersFile::parse(toml).is_ok());
    }

    #[test]
    fn parse_user_entry_with_bandwidth_limit() {
        let users = UsersFile::parse(SAMPLE_USERS_TOML).expect("valid TOML");
        let alice = users.users.get("alice").expect("alice exists");
        assert_eq!(
            alice.bandwidth_limit,
            Some(Bandwidth::from_bytes_per_second(1_250_000))
        );
        let bob = users.users.get("bob").expect("bob exists");
        assert_eq!(bob.bandwidth_limit, None);
    }

    #[test]
    fn same_key_for_same_user_rejected() {
        // A user listing the same key twice should also be rejected as a duplicate
        let toml = r#"
            [users.alice]
            authorized_keys = [
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            ]
        "#;
        let result = UsersFile::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("duplicate Noise X25519 key"), "error: {err}");
    }

    #[test]
    fn parse_user_entry_with_address_pool() {
        let toml = r#"
            [users.alice]
            authorized_keys = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
            address_pool = ["10.0.0.100/32", "10.0.0.101 - 10.0.0.103"]
        "#;
        let users = UsersFile::parse(toml).expect("valid TOML");
        let alice = users.users.get("alice").expect("alice exists");
        assert_eq!(alice.address_pool.len(), 2);
    }

    #[test]
    fn parse_user_entry_without_address_pool() {
        let toml = r#"
            [users.alice]
            authorized_keys = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
        "#;
        let users = UsersFile::parse(toml).expect("valid TOML");
        let alice = users.users.get("alice").expect("alice exists");
        assert!(alice.address_pool.is_empty());
    }

    #[test]
    fn overlapping_address_pools_between_users_rejected() {
        let toml = r#"
            [users.alice]
            authorized_keys = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
            address_pool = ["10.0.0.100/31"]

            [users.bob]
            authorized_keys = ["AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
            address_pool = ["10.0.0.100 - 10.0.0.101"]
        "#;
        let result = UsersFile::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("claimed by both users"), "error: {err}");
    }

    #[test]
    fn duplicate_addresses_within_user_pool_rejected() {
        let toml = r#"
            [users.alice]
            authorized_keys = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
            address_pool = ["10.0.0.100/32", "10.0.0.100/32"]
        "#;
        let result = UsersFile::parse(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("duplicate address"), "error: {err}");
    }
}
