use crate::error::{CertificateError, Result};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::Path;

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
/// ### Arguments
/// - `path` - Path to the file containing the private key.
///
/// ### Returns
/// - `PrivatePkcs8KeyDer` - The loaded private key.
pub fn load_private_key_from_file(path: &Path) -> Result<PrivatePkcs8KeyDer<'static>> {
    let file = File::open(path).map_err(|_| CertificateError::PrivateKeyLoadFailed {
        path: path.to_path_buf(),
    })?;
    let mut reader = BufReader::new(file);

    let key = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .last()
        .ok_or_else(|| CertificateError::PrivateKeyLoadFailed {
            path: path.to_path_buf(),
        })?
        .map_err(|_| CertificateError::PrivateKeyLoadFailed {
            path: path.to_path_buf(),
        })?
        .clone_key();

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const VALID_CERT_PEM: &str = include_str!("../../quincy-tests/tests/static/server_cert.pem");
    const VALID_KEY_PEM: &str = include_str!("../../quincy-tests/tests/static/server_key.pem");

    // ========== load_certificates_from_pem tests ==========

    #[test]
    fn load_certificates_from_pem_valid() {
        let certs = load_certificates_from_pem(VALID_CERT_PEM).unwrap();
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
        let result = load_certificates_from_pem(VALID_KEY_PEM);
        assert!(result.is_err());
    }

    // ========== load_certificates_from_file tests ==========

    #[test]
    fn load_certificates_from_file_valid() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(VALID_CERT_PEM.as_bytes()).unwrap();

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
        file.write_all(VALID_KEY_PEM.as_bytes()).unwrap();

        let result = load_certificates_from_file(file.path());
        assert!(result.is_err());
    }

    // ========== load_private_key_from_file tests ==========

    #[test]
    fn load_private_key_from_file_valid() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(VALID_KEY_PEM.as_bytes()).unwrap();

        let result = load_private_key_from_file(file.path());
        assert!(result.is_ok());
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
        file.write_all(VALID_CERT_PEM.as_bytes()).unwrap();

        let result = load_private_key_from_file(file.path());
        assert!(result.is_err());
    }
}
