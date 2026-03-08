//! Prometheus metrics endpoint for the Quincy VPN server.
//!
//! When enabled, installs a global Prometheus recorder with a built-in HTTP
//! server that exposes a `/metrics` endpoint compatible with Prometheus
//! scraping. Metrics are updated by per-connection tasks using the `metrics`
//! crate's lock-free atomic counters and gauges.

use std::net::SocketAddr;
use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;
use tracing::info;

use quincy::config::MetricsConfig;
use quincy::error::{MetricsError, Result};

/// Initializes the Prometheus metrics recorder and spawns the HTTP server.
///
/// Installs a global recorder and spawns an HTTP server (via
/// `PrometheusBuilder::install`) into the current Tokio runtime. The server
/// binds to `config.address:config.port` and serves metrics in Prometheus
/// text exposition format.
///
/// When `idle_timeout_s` is non-zero, metrics that have not been updated
/// within the timeout are evicted from the registry on the next scrape.
/// This prevents stale per-connection metrics from accumulating after
/// clients disconnect.
///
/// ### Errors
/// Returns `MetricsError::RecorderInstallFailed` if the global recorder
/// cannot be installed or the HTTP server cannot bind.
pub fn init_metrics(config: &MetricsConfig) -> Result<()> {
    let addr = SocketAddr::new(config.address, config.port);

    let idle_timeout = match config.idle_timeout_s {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    };

    PrometheusBuilder::new()
        .with_http_listener(addr)
        .idle_timeout(MetricKindMask::ALL, idle_timeout)
        .install()
        .map_err(|e| MetricsError::RecorderInstallFailed {
            reason: e.to_string(),
        })?;

    info!("Metrics endpoint listening on http://{addr}/metrics");

    Ok(())
}
