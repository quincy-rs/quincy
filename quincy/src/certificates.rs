use std::collections::HashSet;
use std::fmt::Debug;
use std::path::Path;
use std::{
    fs::File,
    io::{BufReader, Cursor},
};

use aws_lc_rs::digest;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

use crate::error::{CertificateError, Result};

/// Loads certificates from a file.
///
/// ### Arguments
/// - `path` - Path to the file containing the certificates.
///
/// ### Returns
/// - `Vec<CertificateDer>` - A list of loaded certificates.
pub fn load_certificates_from_file(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).map_err(|_| CertificateError::LoadFailed {
        path: path.to_path_buf(),
    })?;
    let mut reader = BufReader::new(file);

    let certs: std::result::Result<Vec<CertificateDer>, _> =
        rustls_pemfile::certs(&mut reader).collect();

    let certs = certs.map_err(|_| CertificateError::LoadFailed {
        path: path.to_path_buf(),
    })?;

    if certs.is_empty() {
        return Err(CertificateError::LoadFailed {
            path: path.to_path_buf(),
        }
        .into());
    }

    Ok(certs)
}

/// Loads certificates from a PEM string.
///
/// ### Arguments
/// - `pem_data` - PEM-encoded certificate data as a string.
///
/// ### Returns
/// - `Vec<CertificateDer>` - A list of loaded certificates.
pub fn load_certificates_from_pem(pem_data: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = Cursor::new(pem_data.as_bytes());
    let certs: std::result::Result<Vec<CertificateDer>, _> =
        rustls_pemfile::certs(&mut reader).collect();

    let certs = certs.map_err(|_| CertificateError::UnsupportedFormat)?;

    if certs.is_empty() {
        return Err(CertificateError::UnsupportedFormat.into());
    }

    Ok(certs)
}

/// Loads a private key from a file.
///
/// Automatically detects and parses private keys in any supported format:
/// - PKCS8
/// - RSA PKCS1
/// - EC SEC1
///
/// ### Arguments
/// - `path` - Path to the file containing the private key.
///
/// ### Returns
/// - `PrivateKeyDer` - The loaded private key.
pub fn load_private_key_from_file(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(|_| {
        CertificateError::PrivateKeyLoadFailed {
            path: path.to_path_buf(),
        }
        .into()
    })
}

/// Computes the SHA-256 fingerprint of a DER-encoded certificate.
///
/// Returns a string in the format `sha256:<lowercase-hex>`.
///
/// ### Arguments
/// - `cert` - the DER-encoded certificate
pub fn compute_cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    let hash = digest::digest(&digest::SHA256, cert.as_ref());
    let hex: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Custom client certificate verifier for Quincy.
///
/// Validates client certificates by checking whether the leaf certificate's SHA-256
/// fingerprint is present in the allowed set. Client authentication is mandatory --
/// anonymous clients are rejected.
///
/// Fingerprint-based validation does not check certificate expiry. Expired certificates
/// remain valid until their fingerprint is removed from the users file.
pub struct QuincyCertVerifier {
    /// Set of allowed certificate fingerprints in `sha256:<hex>` format.
    allowed_fingerprints: HashSet<String>,
    /// Supported signature verification algorithms.
    supported_algs: WebPkiSupportedAlgorithms,
}

impl QuincyCertVerifier {
    /// Creates a new `QuincyCertVerifier`.
    ///
    /// ### Arguments
    /// - `allowed_fingerprints` - set of allowed certificate fingerprints
    /// - `crypto_provider` - the crypto provider for signature verification algorithms
    pub fn new(allowed_fingerprints: HashSet<String>, crypto_provider: &CryptoProvider) -> Self {
        Self {
            allowed_fingerprints,
            supported_algs: crypto_provider.signature_verification_algorithms,
        }
    }
}

impl Debug for QuincyCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuincyCertVerifier")
            .field(
                "allowed_fingerprints_count",
                &self.allowed_fingerprints.len(),
            )
            .finish()
    }
}

impl ClientCertVerifier for QuincyCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, Error> {
        let fingerprint = compute_cert_fingerprint(end_entity);
        if self.allowed_fingerprints.contains(&fingerprint) {
            return Ok(ClientCertVerified::assertion());
        }

        Err(Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const VALID_CERT_PEM_PKCS8: &str =
        include_str!("../../quincy-tests/tests/static/server_cert_pkcs8.pem");
    const VALID_KEY_PEM_PKCS8: &str =
        include_str!("../../quincy-tests/tests/static/server_key_pkcs8.pem");
    const VALID_KEY_PEM_RSA_PKCS1: &str =
        include_str!("../../quincy-tests/tests/static/server_key_rsa_pkcs1.pem");
    const VALID_KEY_PEM_EC_SEC1: &str =
        include_str!("../../quincy-tests/tests/static/server_key_ec_sec1.pem");

    // ========== compute_cert_fingerprint tests ==========

    #[test]
    fn compute_fingerprint_deterministic() {
        let certs = load_certificates_from_pem(VALID_CERT_PEM_PKCS8).unwrap();
        let fp1 = compute_cert_fingerprint(&certs[0]);
        let fp2 = compute_cert_fingerprint(&certs[0]);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("sha256:"));
        // SHA-256 produces 64 hex chars
        assert_eq!(fp1.len(), "sha256:".len() + 64);
    }

    #[test]
    fn compute_fingerprint_lowercase_hex() {
        let certs = load_certificates_from_pem(VALID_CERT_PEM_PKCS8).unwrap();
        let fp = compute_cert_fingerprint(&certs[0]);
        let hex_part = fp.strip_prefix("sha256:").unwrap();
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hex_part, hex_part.to_lowercase());
    }

    // ========== load_certificates_from_pem tests ==========

    #[test]
    fn load_certificates_from_pem_valid() {
        let certs = load_certificates_from_pem(VALID_CERT_PEM_PKCS8).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn load_certificates_from_pem_empty_string() {
        let result = load_certificates_from_pem("");
        assert!(result.is_err());
    }

    #[test]
    fn load_certificates_from_pem_path_string() {
        let result = load_certificates_from_pem("/path/to/cert.pem");
        assert!(result.is_err());
    }

    #[test]
    fn load_certificates_from_pem_invalid_pem() {
        let result = load_certificates_from_pem("not a valid pem");
        assert!(result.is_err());
    }

    #[test]
    fn load_certificates_from_pem_wrong_pem_type() {
        // Private key PEM should not parse as certificate
        let result = load_certificates_from_pem(VALID_KEY_PEM_PKCS8);
        assert!(result.is_err());
    }

    // ========== load_certificates_from_file tests ==========

    #[test]
    fn load_certificates_from_file_valid() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(VALID_CERT_PEM_PKCS8.as_bytes()).unwrap();

        let certs = load_certificates_from_file(file.path()).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn load_certificates_from_file_nonexistent() {
        let result = load_certificates_from_file(Path::new("/nonexistent/path/cert.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn load_certificates_from_file_empty() {
        let file = NamedTempFile::new().unwrap();

        let result = load_certificates_from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn load_certificates_from_file_invalid_content() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not a valid certificate").unwrap();

        let result = load_certificates_from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn load_certificates_from_file_wrong_pem_type() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(VALID_KEY_PEM_PKCS8.as_bytes()).unwrap();

        let result = load_certificates_from_file(file.path());
        assert!(result.is_err());
    }

    // ========== load_private_key_from_file tests ==========

    #[test]
    fn load_private_key_from_file_valid_pkcs8() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(VALID_KEY_PEM_PKCS8.as_bytes()).unwrap();

        let result = load_private_key_from_file(file.path());
        assert!(result.is_ok());
        // Verify it's PKCS8 format
        if let Ok(PrivateKeyDer::Pkcs8(_)) = result {
            // Success
        } else {
            panic!("Expected PKCS8 key format");
        }
    }

    #[test]
    fn load_private_key_from_file_valid_rsa_pkcs1() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(VALID_KEY_PEM_RSA_PKCS1.as_bytes()).unwrap();

        let result = load_private_key_from_file(file.path());
        assert!(result.is_ok());
        // Verify it's PKCS1 (RSA) format
        if let Ok(PrivateKeyDer::Pkcs1(_)) = result {
            // Success
        } else {
            panic!("Expected PKCS1 (RSA) key format");
        }
    }

    #[test]
    fn load_private_key_from_file_valid_ec_sec1() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(VALID_KEY_PEM_EC_SEC1.as_bytes()).unwrap();

        let result = load_private_key_from_file(file.path());
        assert!(result.is_ok());
        // Verify it's SEC1 (EC) format
        if let Ok(PrivateKeyDer::Sec1(_)) = result {
            // Success
        } else {
            panic!("Expected SEC1 (EC) key format");
        }
    }

    #[test]
    fn load_private_key_from_file_nonexistent() {
        let result = load_private_key_from_file(Path::new("/nonexistent/path/key.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn load_private_key_from_file_empty() {
        let file = NamedTempFile::new().unwrap();

        let result = load_private_key_from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn load_private_key_from_file_invalid_content() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not a valid key").unwrap();

        let result = load_private_key_from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn load_private_key_from_file_wrong_pem_type() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(VALID_CERT_PEM_PKCS8.as_bytes()).unwrap();

        let result = load_private_key_from_file(file.path());
        assert!(result.is_err());
    }
}
