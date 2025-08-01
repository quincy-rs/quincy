use anyhow::Result;
use anyhow::{anyhow, Context};
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
    let file = File::open(path).context(format!(
        "failed to load certificate file '{}'",
        path.display()
    ))?;
    let mut reader = BufReader::new(file);

    let certs: Result<Vec<CertificateDer>, _> = rustls_pemfile::certs(&mut reader).collect();

    Ok(certs?)
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
    let certs: Result<Vec<CertificateDer>, _> = rustls_pemfile::certs(&mut reader).collect();
    Ok(certs?)
}

/// Loads a private key from a file.
///
/// ### Arguments
/// - `path` - Path to the file containing the private key.
///
/// ### Returns
/// - `PrivatePkcs8KeyDer` - The loaded private key.
pub fn load_private_key_from_file(path: &Path) -> Result<PrivatePkcs8KeyDer<'static>> {
    let file = File::open(path).context(format!(
        "failed to load private key file '{}'",
        path.display()
    ))?;
    let mut reader = BufReader::new(file);

    Ok(rustls_pemfile::pkcs8_private_keys(&mut reader)
        .last()
        .ok_or(anyhow!("No private key found in file"))??
        .clone_key())
}
