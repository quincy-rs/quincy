use quincy::error::ConfigError;
use quincy::{QuincyError, Result};
use regex::Regex;
use std::sync::OnceLock;

/// Compiled regex for valid configuration/instance names.
///
/// Pattern allows ASCII letters, digits, '-' and '_'.
/// Names must be non-empty.
static NAME_RE: OnceLock<Regex> = OnceLock::new();

fn name_re() -> &'static Regex {
    NAME_RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]+$").expect("valid name regex"))
}

/// Returns true if the provided name matches the allowed pattern.
///
/// Allowed: ASCII letters, digits, spaces, '-' and '_'.
pub fn is_valid_config_name(name: &str) -> bool {
    !name.is_empty() && name_re().is_match(name)
}

/// Validates a configuration file/display name.
///
/// Returns a `ConfigError::InvalidValue` on failure with a descriptive reason.
pub fn validate_config_name(name: &str) -> Result<()> {
    is_valid_config_name(name).then_some(()).ok_or_else(|| {
        QuincyError::Config(ConfigError::InvalidValue {
            field: "config_name".to_string(),
            reason: "contains unsupported characters (allowed: letters, digits, '-', '_')"
                .to_string(),
        })
    })
}

/// Validates an instance name (used for IPC identification).
///
/// Uses the same rules as configuration names but distinguishes the field for clearer errors.
pub fn validate_instance_name(name: &str) -> Result<()> {
    is_valid_config_name(name).then_some(()).ok_or_else(|| {
        QuincyError::Config(ConfigError::InvalidValue {
            field: "instance_name".to_string(),
            reason: "contains unsupported characters (allowed: letters, digits, '-', '_')"
                .to_string(),
        })
    })
}
