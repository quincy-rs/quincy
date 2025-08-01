use tracing::Subscriber;
use tracing_subscriber::fmt::SubscriberBuilder;
use tracing_subscriber::EnvFilter;

/// Returns a new `tracing` subscriber with the specified log level.
///
/// ### Arguments
/// - `log_level` - the log level to use
pub fn log_subscriber(log_level: &str) -> impl Subscriber {
    // Enable ANSI color support on Windows.
    #[cfg(windows)]
    let with_ansi = nu_ansi_term::enable_ansi_support().is_ok();

    #[cfg(not(windows))]
    let with_ansi = true;

    let filter_layer = EnvFilter::try_new(log_level).unwrap();

    SubscriberBuilder::default()
        .with_env_filter(filter_layer)
        .with_ansi(with_ansi)
        .finish()
}
