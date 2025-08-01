use std::path::PathBuf;
use std::process::exit;

use anyhow::Result;
use clap::Parser;
use quincy::client::QuincyClient;
use quincy::config::{ClientConfig, FromPath};
use quincy::network::interface::tun_rs::TunRsInterface;
use quincy::utils::tracing::log_subscriber;
use tracing::error;

#[derive(Parser)]
#[command(name = "quincy")]
pub struct Args {
    #[arg(long, default_value = "client.toml")]
    pub config_path: PathBuf,
    #[arg(long, default_value = "QUINCY_")]
    pub env_prefix: String,
}

#[tokio::main]
async fn main() {
    // Enable default tracing to log errors before the configuration is loaded.
    let _logger = tracing::subscriber::set_default(log_subscriber("info"));

    match run_client().await {
        Ok(_) => {}
        Err(e) => {
            error!("A critical error occurred: {e}");
            exit(1);
        }
    }
}

/// Runs the Quincy client.
async fn run_client() -> Result<()> {
    let args = Args::parse();
    let config = ClientConfig::from_path(&args.config_path, &args.env_prefix)?;
    // Enable tracing with the log level from the configuration.
    tracing::subscriber::set_global_default(log_subscriber(&config.log.level))?;

    let mut client: QuincyClient<TunRsInterface> = QuincyClient::new(config);
    client.start().await?;
    client.wait_for_shutdown().await
}
