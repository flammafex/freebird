// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Human-readable duration parsing utilities.
//!
//! This module provides functions to parse duration strings in human-readable
//! formats like "30d", "1h", "5m", "30s" into seconds, with fallback to raw
//! seconds for backward compatibility.
//!
//! # Supported formats
//!
//! - `30d` - 30 days
//! - `24h` - 24 hours
//! - `30m` - 30 minutes
//! - `45s` - 45 seconds
//! - `2592000` - raw seconds (backward compatible)
//! - `1d12h` - combined: 1 day and 12 hours
//! - `1h30m` - combined: 1 hour and 30 minutes
//!
//! # Examples
//!
//! ```
//! use freebird_common::duration::parse_duration;
//!
//! assert_eq!(parse_duration("30d").unwrap(), 2592000);
//! assert_eq!(parse_duration("1h").unwrap(), 3600);
//! assert_eq!(parse_duration("5m").unwrap(), 300);
//! assert_eq!(parse_duration("30s").unwrap(), 30);
//! assert_eq!(parse_duration("3600").unwrap(), 3600); // backward compat
//! assert_eq!(parse_duration("1d12h").unwrap(), 129600); // combined
//! ```

use std::fmt;

/// Error type for duration parsing failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDurationError {
    input: String,
    reason: String,
}

impl fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid duration '{}': {}",
            self.input, self.reason
        )
    }
}

impl std::error::Error for ParseDurationError {}

/// Parse a human-readable duration string into seconds.
///
/// Supports formats like:
/// - `30d` - 30 days (30 * 86400 = 2592000 seconds)
/// - `24h` - 24 hours (24 * 3600 = 86400 seconds)
/// - `30m` - 30 minutes (30 * 60 = 1800 seconds)
/// - `45s` - 45 seconds
/// - `2592000` - raw seconds (for backward compatibility)
/// - `1d12h` - combined durations (1 day + 12 hours)
/// - `1h30m` - combined durations (1 hour + 30 minutes)
///
/// # Arguments
///
/// * `input` - A duration string to parse
///
/// # Returns
///
/// The duration in seconds, or an error if parsing fails.
///
/// # Examples
///
/// ```
/// use freebird_common::duration::parse_duration;
///
/// // Simple units
/// assert_eq!(parse_duration("30d").unwrap(), 2592000);
/// assert_eq!(parse_duration("1h").unwrap(), 3600);
/// assert_eq!(parse_duration("5m").unwrap(), 300);
/// assert_eq!(parse_duration("30s").unwrap(), 30);
///
/// // Raw seconds (backward compatible)
/// assert_eq!(parse_duration("3600").unwrap(), 3600);
///
/// // Combined durations
/// assert_eq!(parse_duration("1d12h").unwrap(), 129600);
/// assert_eq!(parse_duration("1h30m").unwrap(), 5400);
/// assert_eq!(parse_duration("1d2h3m4s").unwrap(), 93784);
/// ```
pub fn parse_duration(input: &str) -> Result<u64, ParseDurationError> {
    let input = input.trim();

    if input.is_empty() {
        return Err(ParseDurationError {
            input: input.to_string(),
            reason: "empty string".to_string(),
        });
    }

    // Try parsing as raw seconds first (backward compatibility)
    if let Ok(secs) = input.parse::<u64>() {
        return Ok(secs);
    }

    // Parse combined duration string (e.g., "1d12h30m")
    let mut total_secs: u64 = 0;
    let mut current_num = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            current_num.push(c);
        } else if c.is_ascii_alphabetic() {
            if current_num.is_empty() {
                return Err(ParseDurationError {
                    input: input.to_string(),
                    reason: format!("expected number before '{}'", c),
                });
            }

            let num: u64 = current_num.parse().map_err(|_| ParseDurationError {
                input: input.to_string(),
                reason: format!("invalid number '{}'", current_num),
            })?;
            current_num.clear();

            let multiplier = match c.to_ascii_lowercase() {
                'd' => 86400,  // days
                'h' => 3600,   // hours
                'm' => 60,     // minutes
                's' => 1,      // seconds
                _ => {
                    return Err(ParseDurationError {
                        input: input.to_string(),
                        reason: format!(
                            "unknown unit '{}' (supported: d=days, h=hours, m=minutes, s=seconds)",
                            c
                        ),
                    });
                }
            };

            total_secs = total_secs.checked_add(num.checked_mul(multiplier).ok_or_else(|| {
                ParseDurationError {
                    input: input.to_string(),
                    reason: "duration overflow".to_string(),
                }
            })?).ok_or_else(|| ParseDurationError {
                input: input.to_string(),
                reason: "duration overflow".to_string(),
            })?;
        } else if !c.is_whitespace() {
            return Err(ParseDurationError {
                input: input.to_string(),
                reason: format!("unexpected character '{}'", c),
            });
        }
    }

    // Check if there's a trailing number without a unit
    if !current_num.is_empty() {
        return Err(ParseDurationError {
            input: input.to_string(),
            reason: format!(
                "number '{}' missing unit (use d=days, h=hours, m=minutes, s=seconds)",
                current_num
            ),
        });
    }

    if total_secs == 0 && !input.chars().any(|c| c.is_ascii_alphabetic()) {
        return Err(ParseDurationError {
            input: input.to_string(),
            reason: "no valid duration components found".to_string(),
        });
    }

    Ok(total_secs)
}

/// Format a duration in seconds as a human-readable string.
///
/// This is the inverse of `parse_duration`. Useful for displaying
/// configuration values or in error messages.
///
/// # Examples
///
/// ```
/// use freebird_common::duration::format_duration;
///
/// assert_eq!(format_duration(86400), "1d");
/// assert_eq!(format_duration(3600), "1h");
/// assert_eq!(format_duration(60), "1m");
/// assert_eq!(format_duration(30), "30s");
/// assert_eq!(format_duration(90061), "1d1h1m1s");
/// assert_eq!(format_duration(0), "0s");
/// ```
pub fn format_duration(mut secs: u64) -> String {
    if secs == 0 {
        return "0s".to_string();
    }

    let mut parts = Vec::new();

    let days = secs / 86400;
    if days > 0 {
        parts.push(format!("{}d", days));
        secs %= 86400;
    }

    let hours = secs / 3600;
    if hours > 0 {
        parts.push(format!("{}h", hours));
        secs %= 3600;
    }

    let minutes = secs / 60;
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
        secs %= 60;
    }

    if secs > 0 {
        parts.push(format!("{}s", secs));
    }

    parts.join("")
}

/// Parse a duration from an environment variable with a default value.
///
/// This is a convenience function for configuration loading. It reads
/// the environment variable, parses it as a duration, and returns the
/// default if the variable is not set or parsing fails.
///
/// # Arguments
///
/// * `key` - The environment variable name
/// * `default` - The default value in seconds if the variable is not set
///
/// # Returns
///
/// The parsed duration in seconds, or the default value.
///
/// # Examples
///
/// ```
/// use freebird_common::duration::env_duration;
///
/// // Returns default if not set
/// std::env::remove_var("TEST_DURATION_XYZ");
/// assert_eq!(env_duration("TEST_DURATION_XYZ", 3600), 3600);
///
/// // Parses human-readable format
/// std::env::set_var("TEST_DURATION_XYZ", "1h");
/// assert_eq!(env_duration("TEST_DURATION_XYZ", 0), 3600);
///
/// // Also accepts raw seconds for backward compatibility
/// std::env::set_var("TEST_DURATION_XYZ", "7200");
/// assert_eq!(env_duration("TEST_DURATION_XYZ", 0), 7200);
///
/// // Clean up
/// std::env::remove_var("TEST_DURATION_XYZ");
/// ```
pub fn env_duration(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| parse_duration(&s).ok())
        .unwrap_or(default)
}

/// Parse a duration with validation that it falls within acceptable bounds.
///
/// Returns an error if the duration is outside the specified range.
///
/// # Arguments
///
/// * `input` - A duration string to parse
/// * `min_secs` - Minimum acceptable value in seconds
/// * `max_secs` - Maximum acceptable value in seconds
///
/// # Examples
///
/// ```
/// use freebird_common::duration::parse_duration_bounded;
///
/// // Within bounds
/// assert!(parse_duration_bounded("1h", 60, 86400).is_ok());
///
/// // Below minimum
/// assert!(parse_duration_bounded("30s", 60, 86400).is_err());
///
/// // Above maximum
/// assert!(parse_duration_bounded("2d", 60, 86400).is_err());
/// ```
pub fn parse_duration_bounded(
    input: &str,
    min_secs: u64,
    max_secs: u64,
) -> Result<u64, ParseDurationError> {
    let secs = parse_duration(input)?;

    if secs < min_secs {
        return Err(ParseDurationError {
            input: input.to_string(),
            reason: format!(
                "duration {} is below minimum {} ({})",
                format_duration(secs),
                format_duration(min_secs),
                min_secs
            ),
        });
    }

    if secs > max_secs {
        return Err(ParseDurationError {
            input: input.to_string(),
            reason: format!(
                "duration {} exceeds maximum {} ({})",
                format_duration(secs),
                format_duration(max_secs),
                max_secs
            ),
        });
    }

    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_parse_simple_units() {
        assert_eq!(parse_duration("30d").unwrap(), 30 * 86400);
        assert_eq!(parse_duration("7d").unwrap(), 7 * 86400);
        assert_eq!(parse_duration("1d").unwrap(), 86400);

        assert_eq!(parse_duration("24h").unwrap(), 24 * 3600);
        assert_eq!(parse_duration("1h").unwrap(), 3600);

        assert_eq!(parse_duration("30m").unwrap(), 30 * 60);
        assert_eq!(parse_duration("5m").unwrap(), 300);

        assert_eq!(parse_duration("45s").unwrap(), 45);
        assert_eq!(parse_duration("1s").unwrap(), 1);
    }

    #[test]
    fn test_parse_raw_seconds() {
        assert_eq!(parse_duration("0").unwrap(), 0);
        assert_eq!(parse_duration("60").unwrap(), 60);
        assert_eq!(parse_duration("3600").unwrap(), 3600);
        assert_eq!(parse_duration("86400").unwrap(), 86400);
        assert_eq!(parse_duration("2592000").unwrap(), 2592000);
    }

    #[test]
    fn test_parse_combined() {
        assert_eq!(parse_duration("1d12h").unwrap(), 86400 + 12 * 3600);
        assert_eq!(parse_duration("1h30m").unwrap(), 3600 + 30 * 60);
        assert_eq!(parse_duration("1d2h3m4s").unwrap(), 86400 + 2 * 3600 + 3 * 60 + 4);
        assert_eq!(parse_duration("2d12h30m").unwrap(), 2 * 86400 + 12 * 3600 + 30 * 60);
    }

    #[test]
    fn test_parse_case_insensitive() {
        assert_eq!(parse_duration("1D").unwrap(), 86400);
        assert_eq!(parse_duration("1H").unwrap(), 3600);
        assert_eq!(parse_duration("1M").unwrap(), 60);
        assert_eq!(parse_duration("1S").unwrap(), 1);
        assert_eq!(parse_duration("1d2H3m4S").unwrap(), 86400 + 2 * 3600 + 3 * 60 + 4);
    }

    #[test]
    fn test_parse_with_whitespace() {
        assert_eq!(parse_duration("  30d  ").unwrap(), 30 * 86400);
        assert_eq!(parse_duration("\t1h\n").unwrap(), 3600);
    }

    #[test]
    fn test_parse_errors() {
        // Empty string
        assert!(parse_duration("").is_err());

        // Unknown unit
        assert!(parse_duration("30x").is_err());

        // Missing number
        assert!(parse_duration("d").is_err());

        // Number without unit (only when there are letters)
        assert!(parse_duration("30d20").is_err());

        // Invalid characters
        assert!(parse_duration("30d@").is_err());
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(1), "1s");
        assert_eq!(format_duration(60), "1m");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(86400), "1d");

        assert_eq!(format_duration(90061), "1d1h1m1s");
        assert_eq!(format_duration(129600), "1d12h");
        assert_eq!(format_duration(5400), "1h30m");
    }

    #[test]
    fn test_format_roundtrip() {
        let test_cases = [0, 1, 60, 3600, 86400, 90061, 129600, 2592000];
        for &secs in &test_cases {
            let formatted = format_duration(secs);
            let parsed = parse_duration(&formatted).unwrap();
            assert_eq!(secs, parsed, "roundtrip failed for {} -> {}", secs, formatted);
        }
    }

    #[test]
    fn test_parse_duration_bounded() {
        // Within bounds
        assert_eq!(parse_duration_bounded("1h", 60, 86400).unwrap(), 3600);

        // Exactly at bounds
        assert_eq!(parse_duration_bounded("1m", 60, 86400).unwrap(), 60);
        assert_eq!(parse_duration_bounded("1d", 60, 86400).unwrap(), 86400);

        // Below minimum
        let err = parse_duration_bounded("30s", 60, 86400).unwrap_err();
        assert!(err.to_string().contains("below minimum"));

        // Above maximum
        let err = parse_duration_bounded("2d", 60, 86400).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    #[serial]
    fn test_env_duration() {
        let key = "FREEBIRD_TEST_DURATION_INTERNAL";

        // Test default when not set
        std::env::remove_var(key);
        assert_eq!(env_duration(key, 3600), 3600);

        // Test human-readable format
        std::env::set_var(key, "1h");
        assert_eq!(env_duration(key, 0), 3600);

        // Test raw seconds
        std::env::set_var(key, "7200");
        assert_eq!(env_duration(key, 0), 7200);

        // Test combined format
        std::env::set_var(key, "1h30m");
        assert_eq!(env_duration(key, 0), 5400);

        // Test invalid falls back to default
        std::env::set_var(key, "invalid");
        assert_eq!(env_duration(key, 3600), 3600);

        // Cleanup
        std::env::remove_var(key);
    }
}
