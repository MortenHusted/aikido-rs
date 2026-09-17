//! Parse snooze durations like `7d` into an absolute unix timestamp.
//! Shared by the CLI's `--until` flag and the MCP snooze tool.

/// Upper bound on an `Nd` day count. `chrono::TimeDelta::days` panics past
/// roughly 10^8 days, and both the CLI's error-envelope contract and the MCP
/// server's liveness require that no user-supplied value can abort the
/// process. Ten years is generous for any snooze or look-back window and
/// keeps the arithmetic far from that edge.
pub const MAX_DAYS: i64 = 3650;

/// Parse `7d`-style durations. Returns `(unix_timestamp, yyyy-mm-dd)` for
/// now + N days. The date is rendered in local time, like every other
/// human-facing date in this workspace — the timestamp sent to the API is
/// zone-independent.
pub fn parse_days(input: &str) -> Result<(i64, String), String> {
    let days = day_count(input, "expected format like '7d'")?;
    let expiry = chrono::Utc::now() + days;
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
    let days = day_count(trimmed, "expected a unix timestamp or a duration like '7d'")?;
    Ok((chrono::Utc::now() - days).timestamp())
}

/// The `Nd` day count as a checked duration within [`MAX_DAYS`].
fn day_count(input: &str, format_hint: &str) -> Result<chrono::TimeDelta, String> {
    let days: i64 = input
        .trim()
        .strip_suffix('d')
        .ok_or_else(|| format_hint.to_string())?
        .parse()
        .map_err(|_| "expected a positive number of days".to_string())?;
    if days <= 0 {
        return Err("expected a positive number of days".to_string());
    }
    if days > MAX_DAYS {
        return Err(format!("expected at most {MAX_DAYS} days"));
    }
    chrono::TimeDelta::try_days(days).ok_or_else(|| format!("expected at most {MAX_DAYS} days"))
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

    /// `chrono::TimeDelta::days` panics on huge values; a day count must
    /// always come back as an error, never abort the process.
    #[test]
    fn absurd_day_counts_are_errors_not_panics() {
        for input in ["99999999999999999d", "9223372036854775807d", "3651d"] {
            let err = parse_days(input).unwrap_err();
            assert!(err.contains("at most 3650 days"), "{input}: {err}");
            let err = parse_since(input).unwrap_err();
            assert!(err.contains("at most 3650 days"), "{input}: {err}");
        }
        assert!(parse_days("3650d").is_ok());
        assert!(parse_since("3650d").is_ok());
    }
}
