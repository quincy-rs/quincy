use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Formats byte counts into human-readable strings with appropriate units.
///
/// This function converts byte counts into readable format using binary units
/// (1024-based) with one decimal place precision.
///
/// # Arguments
/// * `bytes` - Number of bytes to format
///
/// # Returns
/// Formatted string with value and unit (e.g., "1.5 MB")
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

/// Formats a duration into a human-readable string showing days, hours, minutes,
/// and seconds. Units with zero values are omitted.
///
/// # Arguments
/// * `duration` - Duration to format
///
/// # Returns
/// A formatted string (e.g., "1d 2h 30m 45s", "5m 23s", "42s")
pub fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();

    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    let mut parts = Vec::new();

    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{seconds}s"));
    }

    parts.join(" ")
}

/// Expands environment variables and home directory shortcuts in file paths.
///
/// This function handles platform-specific path expansion:
/// - On Unix: Expands `~/` to the user's home directory
/// - On Windows: Expands `%AppData%` to the application data directory
///
/// # Arguments
/// * `path` - Path that may contain environment variables or shortcuts
///
/// # Returns
/// Expanded path with environment variables resolved
pub fn expand_path(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();

    #[cfg(unix)]
    if path_str.starts_with("~/") {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(path_str.replacen("~", &home, 1));
        }
    }

    #[cfg(windows)]
    if path_str.contains("%AppData%") {
        if let Ok(app_data) = env::var("APPDATA") {
            return PathBuf::from(path_str.replace("%AppData%", &app_data));
        }
    }

    path.to_path_buf()
}
