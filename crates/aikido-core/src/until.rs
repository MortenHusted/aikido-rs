//! Parse snooze durations like `7d` into an absolute unix timestamp.
//! Shared by the CLI's `--until` flag and the MCP snooze tool.

/// Parse `7d`-style durations. Returns `(unix_timestamp, yyyy-mm-dd)` for
/// now + N days.
pub fn parse_days(input: &str) -> Result<(i64, String), String> {
    let trimmed = input.trim();
    let days: i64 = trimmed
        .strip_suffix('d')
        .ok_or_else(|| "expected format like '7d'".to_string())?
        .parse()
        .map_err(|_| "expected a positive number of days".to_string())?;
    if days <= 0 {
        return Err("expected a positive number of days".to_string());
    }
    let expiry = chrono::Utc::now() + chrono::Duration::days(days);
    Ok((expiry.timestamp(), expiry.format("%Y-%m-%d").to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_days_suffix() {
        let (ts, date) = parse_days("7d").unwrap();
        let expected = chrono::Utc::now() + chrono::Duration::days(7);
        assert!((ts - expected.timestamp()).abs() < 5);
        assert_eq!(date, expected.format("%Y-%m-%d").to_string());
    }

    #[test]
    fn rejects_bad_formats() {
        assert!(parse_days("7").is_err());
        assert!(parse_days("d").is_err());
        assert!(parse_days("0d").is_err());
        assert!(parse_days("-3d").is_err());
        assert!(parse_days("3w").is_err());
    }
}
