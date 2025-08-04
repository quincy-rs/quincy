use anyhow::Result;
use clap::Parser;
use quincy::utils::tracing::log_subscriber;
use quincy_gui::gui::{expand_path, QuincyGui};
use std::path::PathBuf;
use tracing::info;

/// The default configuration directory for Quincy, based on the operating system.
#[cfg(target_os = "windows")]
const DEFAULT_CONFIG_DIR: &str = "%AppData%/quincy";
#[cfg(unix)]
const DEFAULT_CONFIG_DIR: &str = "~/.config/quincy";

/// Command line arguments for the Quincy GUI client.
#[derive(Parser)]
#[command(name = "quincy")]
pub struct Args {
    /// Configuration directory path
    #[arg(long, default_value = DEFAULT_CONFIG_DIR)]
    pub config_dir: PathBuf,
    /// Environment variable prefix
    #[arg(long, default_value = "QUINCY_")]
    pub env_prefix: String,
}

/// Main entry point for the Quincy GUI application.
///
/// This function initializes logging, parses command line arguments, configures
/// the window settings, and starts the Iced GUI framework with the QuincyGui application.
///
/// # Returns
/// * `Ok(())` on successful application completion
/// * `Err` if the GUI framework fails to initialize or run
///
/// # Errors
/// Returns an error if:
/// - Logging initialization fails
/// - Window creation fails
/// - The GUI event loop encounters a fatal error
#[tokio::main]
async fn main() -> Result<()> {
    let _logger = tracing::subscriber::set_global_default(log_subscriber("info"));
    info!("Starting Quincy GUI client");

    let args = Args::parse();
    let config_dir = expand_path(&args.config_dir);

    iced::daemon(QuincyGui::title, QuincyGui::update, QuincyGui::view)
        .theme(QuincyGui::theme)
        .subscription(QuincyGui::subscription)
        .run_with(|| QuincyGui::new(config_dir))?;

    Ok(())
}
