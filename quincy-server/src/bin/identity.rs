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

use aws_lc_rs::digest;
use base64::prelude::*;
use clap::{Parser, Subcommand, ValueEnum};
use rand_core::OsRng;
use rcgen::{CertificateParams, KeyPair as RcgenKeyPair};
use reishi_quinn::{KeyPair, PqKeyPair};
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process;

/// Key exchange mode for Noise keypair generation.
#[derive(Clone, Debug, ValueEnum)]
enum KeyExchangeMode {
    /// X25519 Diffie-Hellman
    Standard,
    /// X25519 + ML-KEM-768 hybrid
    Hybrid,
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
        key_exchange: KeyExchangeMode,
    },
    /// Derive the public key from a private key read from stdin
    Pubkey {
        /// The key exchange mode of the private key
        #[arg(short, long, default_value = "standard")]
        key_exchange: KeyExchangeMode,
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
            NoiseCommand::Genkey { key_exchange } => noise_genkey(key_exchange),
            NoiseCommand::Pubkey { key_exchange } => noise_pubkey(key_exchange),
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
fn noise_genkey(key_exchange: KeyExchangeMode) {
    match key_exchange {
        KeyExchangeMode::Standard => {
            let kp = KeyPair::generate(&mut OsRng);
            println!("{}", BASE64_STANDARD.encode(kp.secret_bytes()));
        }
        KeyExchangeMode::Hybrid => {
            let kp = PqKeyPair::generate(&mut OsRng);
            println!("{}", BASE64_STANDARD.encode(kp.secret_bytes()));
        }
    }
}

/// Reads a base64-encoded Noise private key from stdin and prints the derived public key.
fn noise_pubkey(key_exchange: KeyExchangeMode) {
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

    let bytes = match BASE64_STANDARD.decode(&line) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: invalid base64 input: {e}");
            process::exit(1);
        }
    };

    match key_exchange {
        KeyExchangeMode::Standard => {
            let secret_bytes: [u8; 32] = match bytes.try_into() {
                Ok(b) => b,
                Err(_) => {
                    eprintln!("Error: standard private key must be exactly 32 bytes");
                    process::exit(1);
                }
            };
            let kp = KeyPair::from_secret_bytes(&secret_bytes);
            println!("{}", BASE64_STANDARD.encode(kp.public.as_bytes()));
        }
        KeyExchangeMode::Hybrid => {
            let secret_bytes: [u8; 96] = match bytes.try_into() {
                Ok(b) => b,
                Err(_) => {
                    eprintln!("Error: hybrid private key must be exactly 96 bytes");
                    process::exit(1);
                }
            };
            let kp = PqKeyPair::from_secret_bytes(&secret_bytes);
            println!("{}", BASE64_STANDARD.encode(kp.public.to_bytes()));
        }
    }
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

    fs::write(out_key, keypair.serialize_pem()).unwrap_or_else(|e| {
        eprintln!("Error: failed to write key to {}: {e}", out_key.display());
        process::exit(1);
    });

    // Compute and print fingerprint
    let fingerprint = compute_fingerprint(cert.der());
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

/// Computes the SHA-256 fingerprint of DER-encoded certificate bytes.
///
/// Returns a string in the format `sha256:<lowercase-hex>`.
fn compute_fingerprint(der_bytes: &[u8]) -> String {
    let hash = digest::digest(&digest::SHA256, der_bytes);
    let hex: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}
