//! Unified identity management tool for Quincy VPN.
//!
//! Replaces the former `quincy-keygen` tool with a broader set of identity
//! operations for both Noise and TLS protocol modes.
//!
//! Usage:
//!   quincy-identity noise genkey [--key-exchange standard|hybrid]
//!   quincy-identity noise pubkey [--key-exchange standard|hybrid]
//!   quincy-identity tls gencert --out-cert <path> --out-key <path> [--cn <common-name>]
//!   quincy-identity tls fingerprint --cert <path>

use base64::prelude::*;
use clap::builder::PossibleValue;
use clap::{Parser, Subcommand, ValueEnum};
use quincy::config::NoiseKeyExchange;
use rand_core::OsRng;
use rcgen::{CertificateParams, KeyPair as RcgenKeyPair};
use reishi_quinn::{KeyPair, PqKeyPair};
use rustls::pki_types::CertificateDer;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;
use zeroize::Zeroizing;

/// Newtype wrapper around [`NoiseKeyExchange`] that implements [`clap::ValueEnum`].
///
/// The core `quincy` crate does not depend on `clap`, so we cannot derive
/// `ValueEnum` on `NoiseKeyExchange` directly. This wrapper bridges the gap.
#[derive(Clone, Debug)]
struct KeyExchangeArg(NoiseKeyExchange);

impl ValueEnum for KeyExchangeArg {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            KeyExchangeArg(NoiseKeyExchange::Standard),
            KeyExchangeArg(NoiseKeyExchange::Hybrid),
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        match self.0 {
            NoiseKeyExchange::Standard => {
                Some(PossibleValue::new("standard").help("X25519 Diffie-Hellman"))
            }
            NoiseKeyExchange::Hybrid => {
                Some(PossibleValue::new("hybrid").help("X25519 + ML-KEM-768 hybrid"))
            }
        }
    }
}

impl Default for KeyExchangeArg {
    fn default() -> Self {
        KeyExchangeArg(NoiseKeyExchange::Standard)
    }
}

/// Generate and manage identities for Quincy VPN.
#[derive(Parser)]
#[command(name = "quincy-identity")]
#[command(about = "Generate and manage identities for Quincy VPN")]
struct Args {
    #[command(subcommand)]
    command: ProtocolCommand,
}

/// Top-level subcommand selecting the protocol.
#[derive(Subcommand)]
enum ProtocolCommand {
    /// Noise protocol identity operations
    Noise {
        #[command(subcommand)]
        command: NoiseCommand,
    },
    /// TLS protocol identity operations
    Tls {
        #[command(subcommand)]
        command: TlsCommand,
    },
}

/// Noise identity subcommands.
#[derive(Subcommand)]
enum NoiseCommand {
    /// Generate a private key (raw base64 output, suitable for piping)
    Genkey {
        /// The key exchange mode to generate keys for
        #[arg(short, long, default_value = "standard")]
        key_exchange: KeyExchangeArg,
    },
    /// Derive the public key from a private key read from stdin
    Pubkey {
        /// The key exchange mode of the private key
        #[arg(short, long, default_value = "standard")]
        key_exchange: KeyExchangeArg,
    },
}

/// TLS identity subcommands.
#[derive(Subcommand)]
enum TlsCommand {
    /// Generate a self-signed X.509 certificate and private key
    Gencert {
        /// Output path for the certificate PEM file
        #[arg(long)]
        out_cert: PathBuf,
        /// Output path for the private key PEM file
        #[arg(long)]
        out_key: PathBuf,
        /// Common name (CN) for the certificate subject
        #[arg(long, default_value = "quincy")]
        cn: String,
    },
    /// Compute the SHA-256 fingerprint of a PEM certificate
    Fingerprint {
        /// Path to the certificate PEM file
        #[arg(long)]
        cert: PathBuf,
    },
}

fn main() {
    let args = Args::parse();

    match args.command {
        ProtocolCommand::Noise { command } => match command {
            NoiseCommand::Genkey { key_exchange } => noise_genkey(&key_exchange.0),
            NoiseCommand::Pubkey { key_exchange } => noise_pubkey(&key_exchange.0),
        },
        ProtocolCommand::Tls { command } => match command {
            TlsCommand::Gencert {
                out_cert,
                out_key,
                cn,
            } => tls_gencert(&out_cert, &out_key, &cn),
            TlsCommand::Fingerprint { cert } => tls_fingerprint(&cert),
        },
    }
}

/// Generates a Noise private key and prints it as base64 to stdout.
fn noise_genkey(key_exchange: &NoiseKeyExchange) {
    match key_exchange {
        NoiseKeyExchange::Standard => {
            let kp = KeyPair::generate(&mut OsRng);
            println!("{}", BASE64_STANDARD.encode(kp.secret_bytes()));
        }
        NoiseKeyExchange::Hybrid => {
            let kp = PqKeyPair::generate(&mut OsRng);
            println!("{}", BASE64_STANDARD.encode(kp.secret_bytes()));
        }
    }
}

/// Reads a base64-encoded Noise private key from stdin and prints the derived public key.
///
/// Secret key bytes are wrapped in [`Zeroizing`] to ensure they are zeroed from
/// memory once the public key has been derived.
fn noise_pubkey(key_exchange: &NoiseKeyExchange) {
    let line = match io::stdin().lock().lines().next() {
        Some(Ok(line)) => line.trim().to_string(),
        Some(Err(e)) => {
            eprintln!("Error reading from stdin: {e}");
            process::exit(1);
        }
        None => {
            eprintln!("Error: no input provided on stdin");
            process::exit(1);
        }
    };

    let bytes = Zeroizing::new(match BASE64_STANDARD.decode(&line) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: invalid base64 input: {e}");
            process::exit(1);
        }
    });

    match key_exchange {
        NoiseKeyExchange::Standard => {
            let Ok(secret_bytes) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                eprintln!("Error: standard private key must be exactly 32 bytes");
                process::exit(1);
            };
            let secret_bytes = Zeroizing::new(secret_bytes);
            let kp = KeyPair::from_secret_bytes(&secret_bytes);
            println!("{}", BASE64_STANDARD.encode(kp.public.as_bytes()));
        }
        NoiseKeyExchange::Hybrid => {
            let Ok(secret_bytes) = <[u8; 96]>::try_from(bytes.as_slice()) else {
                eprintln!("Error: hybrid private key must be exactly 96 bytes");
                process::exit(1);
            };
            let secret_bytes = Zeroizing::new(secret_bytes);
            let kp = PqKeyPair::from_secret_bytes(&secret_bytes);
            println!("{}", BASE64_STANDARD.encode(kp.public.to_bytes()));
        }
    }
}

/// Writes a private key file with restrictive permissions (0600 on Unix).
///
/// On Unix systems, the file is created with mode `0o600` (owner read/write only)
/// to prevent other users from reading the key material. On non-Unix platforms,
/// falls back to a standard file write.
fn write_private_key(path: &Path, data: &[u8]) -> io::Result<()> {
    write_private_key_impl(path, data)
}

/// Unix implementation: creates the file with mode 0600 (owner read/write only).
///
/// Uses `create_new(true)` for atomic exclusive creation, which fails if a file
/// already exists at the path. This eliminates the TOCTOU race between checking
/// existence and creating the file, preventing symlink-based attacks.
#[cfg(unix)]
fn write_private_key_impl(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    // create_new(true) atomically creates only if file doesn't exist.
    // This eliminates the TOCTOU race between exists() and file creation.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)
}

/// Non-Unix fallback: writes the file with atomic creation.
///
/// Uses `create_new(true)` to avoid overwriting existing files. Note that on Windows,
/// this does not set restrictive ACLs on the file - administrators should ensure the
/// target directory has appropriate permissions or manually set ACLs on the generated
/// key file to restrict access to the owner only.
#[cfg(not(unix))]
fn write_private_key_impl(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(data)
}

/// Generates a self-signed X.509 certificate and writes the cert and key PEM files.
fn tls_gencert(out_cert: &Path, out_key: &Path, cn: &str) {
    let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap_or_else(|e| {
        eprintln!("Error: invalid certificate parameters: {e}");
        process::exit(1);
    });
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);

    let keypair = RcgenKeyPair::generate().unwrap_or_else(|e| {
        eprintln!("Error: key generation failed: {e}");
        process::exit(1);
    });

    let cert = params.self_signed(&keypair).unwrap_or_else(|e| {
        eprintln!("Error: certificate generation failed: {e}");
        process::exit(1);
    });

    fs::write(out_cert, cert.pem()).unwrap_or_else(|e| {
        eprintln!(
            "Error: failed to write certificate to {}: {e}",
            out_cert.display()
        );
        process::exit(1);
    });

    write_private_key(out_key, keypair.serialize_pem().as_bytes()).unwrap_or_else(|e| {
        eprintln!("Error: failed to write key to {}: {e}", out_key.display());
        process::exit(1);
    });

    // Compute and print fingerprint using the core library's compute_cert_fingerprint
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let fingerprint = quincy::certificates::compute_cert_fingerprint(&cert_der);
    println!("Certificate written to: {}", out_cert.display());
    println!("Private key written to: {}", out_key.display());
    println!("SHA-256 fingerprint: {fingerprint}");
}

/// Loads a certificate from a PEM file and prints its SHA-256 fingerprint.
fn tls_fingerprint(cert_path: &Path) {
    let certs = quincy::certificates::load_certificates_from_file(cert_path).unwrap_or_else(|e| {
        eprintln!(
            "Error: failed to load certificate from {}: {e}",
            cert_path.display()
        );
        process::exit(1);
    });

    let end_entity = certs.first().unwrap_or_else(|| {
        eprintln!("Error: no certificates found in {}", cert_path.display());
        process::exit(1);
    });

    let fingerprint = quincy::certificates::compute_cert_fingerprint(end_entity);
    println!("{fingerprint}");
}
