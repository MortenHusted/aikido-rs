//! Parse snooze durations like `7d` into an absolute unix timestamp.
//! Shared by the CLI's `--until` flag and the MCP snooze tool.

/// Parse `7d`-style durations. Returns `(unix_timestamp, yyyy-mm-dd)` for
/// now + N days. The date is rendered in local time, like every other
/// human-facing date in this workspace — the timestamp sent to the API is
/// zone-independent.
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
    let local_date = expiry
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d")
        .to_string();
    Ok((expiry.timestamp(), local_date))
}

/// Parse a `--since` value: `7d`-style (the last N days, i.e. now − N days)
/// or a raw unix-seconds timestamp.
pub fn parse_since(input: &str) -> Result<i64, String> {
    let trimmed = input.trim();
    if let Ok(ts) = trimmed.parse::<i64>() {
        if ts <= 0 {
            return Err("expected a positive unix timestamp".to_string());
        }
        return Ok(ts);
    }
    let days: i64 = trimmed
        .strip_suffix('d')
        .ok_or_else(|| "expected a unix timestamp or a duration like '7d'".to_string())?
        .parse()
        .map_err(|_| "expected a positive number of days".to_string())?;
    if days <= 0 {
        return Err("expected a positive number of days".to_string());
    }
    Ok((chrono::Utc::now() - chrono::Duration::days(days)).timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_days_suffix() {
        let (ts, date) = parse_days("7d").unwrap();
        let expected = chrono::Utc::now() + chrono::Duration::days(7);
        assert!((ts - expected.timestamp()).abs() < 5);
        assert_eq!(
            date,
            expected
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d")
                .to_string()
        );
    }

    #[test]
    fn rejects_bad_formats() {
        assert!(parse_days("7").is_err());
        assert!(parse_days("d").is_err());
        assert!(parse_days("0d").is_err());
        assert!(parse_days("-3d").is_err());
        assert!(parse_days("3w").is_err());
    }

    #[test]
    fn since_accepts_days_ago_and_raw_timestamps() {
        let ts = parse_since("7d").unwrap();
        let expected = (chrono::Utc::now() - chrono::Duration::days(7)).timestamp();
        assert!((ts - expected).abs() < 5, "7d must mean seven days AGO");

        assert_eq!(parse_since("1750000000").unwrap(), 1_750_000_000);
    }

    #[test]
    fn since_rejects_garbage() {
        assert!(parse_since("-5").is_err());
        assert!(parse_since("0d").is_err());
        assert!(parse_since("next tuesday").is_err());
    }
}
