use base64::prelude::*;
use clap::{Parser, Subcommand, ValueEnum};
use rand_core::OsRng;
use reishi_quinn::{KeyPair, PqKeyPair};
use std::io::{self, BufRead};
use std::process;

/// Key exchange mode for Noise keypair generation.
#[derive(Clone, Debug, ValueEnum)]
enum KeyExchangeMode {
    /// X25519 Diffie-Hellman
    Standard,
    /// X25519 + ML-KEM-768 hybrid
    Hybrid,
}

/// Generate and manage Noise keypairs for Quincy.
#[derive(Parser)]
#[command(name = "quincy-keygen")]
#[command(about = "Generate and manage Noise keypairs for Quincy")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

/// Available keygen subcommands.
#[derive(Subcommand)]
enum Command {
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

fn main() {
    let args = Args::parse();

    match args.command {
        Command::Genkey { key_exchange } => genkey(key_exchange),
        Command::Pubkey { key_exchange } => pubkey(key_exchange),
    }
}

/// Generates a private key and prints it as base64 to stdout.
fn genkey(key_exchange: KeyExchangeMode) {
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

/// Reads a base64-encoded private key from stdin and prints the derived public key.
fn pubkey(key_exchange: KeyExchangeMode) {
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
            let kp = KeyPair::from_secret_bytes(secret_bytes);
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
            let kp = PqKeyPair::from_secret_bytes(secret_bytes);
            println!("{}", BASE64_STANDARD.encode(kp.public.to_bytes()));
        }
    }
}
