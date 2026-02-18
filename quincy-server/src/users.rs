//! Users file parser for Quincy VPN.
//!
//! Parses a TOML-formatted users file that maps usernames to their authorized
//! keys and certificates for handshake-layer authentication. Pre-builds
//! lookup indices for O(1) key and fingerprint resolution.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use figment::{
    providers::{Format, Toml},
    Figment,
};
use reishi_quinn::{PqPublicKey, PublicKey};
use serde::Deserialize;

use quincy::config::decode_base64_key;
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
}

impl UsersFile {
    /// Loads and parses a users file from the given path.
    ///
    /// ### Arguments
    /// - `path` - path to the TOML users file
    ///
    /// ### Errors
    /// Returns `AuthError::StoreUnavailable` if the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(AuthError::StoreUnavailable.into());
        }

        let figment = Figment::new().merge(Toml::file(path));
        let raw: RawUsersFile = figment.extract().map_err(|_| AuthError::StoreUnavailable)?;

        Ok(Self::from_raw(raw))
    }

    /// Parses a users file from a TOML string.
    ///
    /// ### Arguments
    /// - `content` - TOML content as a string
    ///
    /// ### Errors
    /// Returns `AuthError::StoreUnavailable` if the content cannot be parsed.
    pub fn parse(content: &str) -> Result<Self> {
        let figment = Figment::new().merge(Toml::string(content));
        let raw: RawUsersFile = figment.extract().map_err(|_| AuthError::StoreUnavailable)?;

        Ok(Self::from_raw(raw))
    }

    /// Builds a `UsersFile` with pre-computed lookup indices from raw deserialized data.
    fn from_raw(raw: RawUsersFile) -> Self {
        let mut noise_key_to_user = HashMap::new();
        let mut noise_pq_key_to_user = HashMap::new();
        let mut cert_fingerprint_to_user = HashMap::new();

        for (username, entry) in &raw.users {
            for key_b64 in &entry.authorized_keys {
                // Try as X25519 key (exactly 32 bytes)
                if let Ok(bytes) = decode_base64_key::<{ PublicKey::LEN }>(key_b64) {
                    noise_key_to_user.insert(PublicKey::from_bytes(*bytes), username.clone());
                }

                // Try as PQ key (validated by from_bytes after length-checked decode)
                if let Ok(bytes) = decode_base64_key::<{ PqPublicKey::LEN }>(key_b64) {
                    noise_pq_key_to_user.insert(PqPublicKey::from_bytes(*bytes), username.clone());
                }
            }

            for fp in &entry.authorized_certs {
                cert_fingerprint_to_user.insert(fp.clone(), username.clone());
            }
        }

        Self {
            users: raw.users,
            noise_key_to_user,
            noise_pq_key_to_user,
            cert_fingerprint_to_user,
        }
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
            .get(fingerprint)
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
        authorized_certs = ["sha256:abcdef1234567890"]

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
            users.find_user_by_cert_fingerprint("sha256:abcdef1234567890"),
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
        assert!(fps.contains("sha256:abcdef1234567890"));
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
                .get("sha256:abcdef1234567890")
                .unwrap(),
            "alice"
        );
    }
}
