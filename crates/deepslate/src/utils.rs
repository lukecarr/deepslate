//! Utility functions for configuration and environment handling.

use std::env;

/// Error type for environment variable parsing.
pub type EnvError = Box<dyn std::error::Error + Send + Sync>;

/// Parse an environment variable as a boolean, with a default value.
///
/// Valid values (case-insensitive): "true", "1", "false", "0".
/// Returns an error for any other value to prevent misconfiguration.
///
/// # Errors
///
/// Returns an error if the environment variable is set to an invalid value,
/// or if the value contains invalid Unicode.
pub fn env_bool(name: &str, default: bool) -> Result<bool, EnvError> {
    let value = match env::var(name) {
        Ok(v) => v,
        Err(env::VarError::NotPresent) => return Ok(default),
        Err(e) => return Err(format!("{name}: {e}").into()),
    };

    match value.to_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!(
            "{name}: invalid value '{value}' (expected 'true', 'false', '1', or '0')"
        )
        .into()),
    }
}

/// Parse an environment variable as a u32, with a default value.
///
/// # Errors
///
/// Returns an error if the environment variable is set to an invalid value,
/// or if the value contains invalid Unicode.
pub fn env_u32(name: &str, default: u32) -> Result<u32, EnvError> {
    let value = match env::var(name) {
        Ok(v) => v,
        Err(env::VarError::NotPresent) => return Ok(default),
        Err(e) => return Err(format!("{name}: {e}").into()),
    };

    value.parse().map_err(|e| format!("{name}: {e}").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to ensure env var tests don't run concurrently
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn with_env_var<F, R>(name: &str, value: Option<&str>, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = ENV_MUTEX.lock().unwrap();

        // Save original value
        let original = env::var(name).ok();

        // Set or remove the variable
        // SAFETY: We hold ENV_MUTEX to ensure single-threaded access to env vars in tests
        unsafe {
            match value {
                Some(v) => env::set_var(name, v),
                None => env::remove_var(name),
            }
        }

        let result = f();

        // Restore original value
        // SAFETY: We hold ENV_MUTEX to ensure single-threaded access to env vars in tests
        unsafe {
            match original {
                Some(v) => env::set_var(name, v),
                None => env::remove_var(name),
            }
        }

        result
    }

    #[test]
    fn test_env_bool_true_values() {
        with_env_var("TEST_BOOL", Some("true"), || {
            assert!(env_bool("TEST_BOOL", false).unwrap());
        });

        with_env_var("TEST_BOOL", Some("TRUE"), || {
            assert!(env_bool("TEST_BOOL", false).unwrap());
        });

        with_env_var("TEST_BOOL", Some("True"), || {
            assert!(env_bool("TEST_BOOL", false).unwrap());
        });

        with_env_var("TEST_BOOL", Some("1"), || {
            assert!(env_bool("TEST_BOOL", false).unwrap());
        });
    }

    #[test]
    fn test_env_bool_false_values() {
        with_env_var("TEST_BOOL", Some("false"), || {
            assert!(!env_bool("TEST_BOOL", true).unwrap());
        });

        with_env_var("TEST_BOOL", Some("FALSE"), || {
            assert!(!env_bool("TEST_BOOL", true).unwrap());
        });

        with_env_var("TEST_BOOL", Some("False"), || {
            assert!(!env_bool("TEST_BOOL", true).unwrap());
        });

        with_env_var("TEST_BOOL", Some("0"), || {
            assert!(!env_bool("TEST_BOOL", true).unwrap());
        });
    }

    #[test]
    fn test_env_bool_default_when_unset() {
        with_env_var("TEST_BOOL_UNSET", None, || {
            assert!(env_bool("TEST_BOOL_UNSET", true).unwrap());
            assert!(!env_bool("TEST_BOOL_UNSET", false).unwrap());
        });
    }

    #[test]
    fn test_env_bool_invalid_value() {
        with_env_var("TEST_BOOL", Some("yes"), || {
            let err = env_bool("TEST_BOOL", false).unwrap_err();
            assert!(err.to_string().contains("invalid value 'yes'"));
            assert!(err.to_string().contains("TEST_BOOL"));
        });

        with_env_var("TEST_BOOL", Some("no"), || {
            let err = env_bool("TEST_BOOL", false).unwrap_err();
            assert!(err.to_string().contains("invalid value 'no'"));
        });

        with_env_var("TEST_BOOL", Some("enabled"), || {
            let err = env_bool("TEST_BOOL", false).unwrap_err();
            assert!(err.to_string().contains("invalid value 'enabled'"));
        });

        with_env_var("TEST_BOOL", Some(""), || {
            let err = env_bool("TEST_BOOL", false).unwrap_err();
            assert!(err.to_string().contains("invalid value ''"));
        });
    }

    #[test]
    fn test_env_bool_error_message_format() {
        with_env_var("MY_VAR", Some("invalid"), || {
            let err = env_bool("MY_VAR", false).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("MY_VAR"));
            assert!(msg.contains("invalid"));
            assert!(msg.contains("expected 'true', 'false', '1', or '0'"));
        });
    }
}
