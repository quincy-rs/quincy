#![windows_subsystem = "windows"]

use clap::Parser;
use iced::daemon;
use quincy::{QuincyError, Result};
use quincy_gui::gui::{expand_path, QuincyGui};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

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
    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    pub log_level: String,
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
fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging: prefer RUST_LOG env var, fall back to CLI arg
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    // Enable ANSI color support on Windows
    #[cfg(windows)]
    let with_ansi = nu_ansi_term::enable_ansi_support().is_ok();
    #[cfg(not(windows))]
    let with_ansi = true;

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(with_ansi)
        .init();

    info!("Starting Quincy GUI client");

    let config_dir = expand_path(&args.config_dir);

    daemon(
        {
            let config_dir = config_dir.clone();
            move || QuincyGui::new(config_dir.clone())
        },
        QuincyGui::update,
        QuincyGui::view,
    )
    .title(QuincyGui::title)
    .theme(QuincyGui::theme)
    .subscription(QuincyGui::subscription)
    .run()
    .map_err(|e| QuincyError::system(format!("GUI framework error: {e}")))?;

    Ok(())
}
