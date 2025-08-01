use std::path::PathBuf;
use std::process::exit;

use anyhow::Result;
use clap::Parser;
use quincy::config::{FromPath, ServerConfig};
use quincy::network::interface::tun_rs::TunRsInterface;
use quincy::server::QuincyServer;
use quincy::utils::tracing::log_subscriber;
use tracing::error;

#[derive(Parser)]
#[command(name = "quincy")]
pub struct Args {
    #[arg(long, default_value = "server.toml")]
    pub config_path: PathBuf,
    #[arg(long, default_value = "QUINCY_")]
    pub env_prefix: String,
}

#[tokio::main]
async fn main() {
    // Enable default tracing to log errors before the configuration is loaded.
    let _logger = tracing::subscriber::set_default(log_subscriber("info"));

    match run_server().await {
        Ok(_) => {}
        Err(e) => {
            error!("A critical error occurred: {e}");
            exit(1)
        }
    }
}

/// Runs the Quincy server.
async fn run_server() -> Result<()> {
    let args = Args::parse();
    let config = ServerConfig::from_path(&args.config_path, &args.env_prefix)?;
    // Enable tracing with the log level from the configuration.
    tracing::subscriber::set_global_default(log_subscriber(&config.log.level))?;

    let server = QuincyServer::new(config)?;
    server.run::<TunRsInterface>().await
}
