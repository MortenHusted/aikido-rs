//! Container scan staleness — the check nobody did for three months.
//!
//! A container whose scanner silently stops reports a *low* finding count,
//! which reads as healthy. This module makes the failure explicit: given a
//! container object from `GET /containers` (unix-second timestamps, `-1`
//! meaning never/unknown), it derives whether the scan is stale and why, so
//! neither the operator nor the scheduled loop has to subtract timestamps
//! by eye.
//!
//! Shared by the CLI (`containers list --stale-days`) and the MCP server so
//! the two can never disagree about what "stale" means.

use serde_json::{json, Value};

/// Why a container's scan coverage is considered stale.
pub const REASON_NEVER_SCANNED: &str = "never_scanned";
pub const REASON_SCAN_OLDER_THAN_LIMIT: &str = "scan_older_than_limit";
pub const REASON_PUSHED_AFTER_SCAN: &str = "pushed_after_scan";

/// Derived scan-freshness facts for one active container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanStaleness {
    /// Days since the last completed scan; `None` when never scanned.
    pub scan_age_days: Option<i64>,
    /// A digest was pushed after the last scan — findings predate the
    /// current image.
    pub pushed_after_scan: bool,
    /// The configured tag filter and the tag actually scanned last disagree
    /// (informational — this was the clue in the original incident, not a
    /// staleness reason by itself).
    pub tag_drift: bool,
    /// Empty when the scan is fresh.
    pub reasons: Vec<&'static str>,
}

impl ScanStaleness {
    pub fn is_stale(&self) -> bool {
        !self.reasons.is_empty()
    }

    /// JSON annotation attached to stale containers in `--stale-days`
    /// output.
    pub fn to_json(&self) -> Value {
        json!({
            "scan_age_days": self.scan_age_days,
            "pushed_after_scan": self.pushed_after_scan,
            "tag_drift": self.tag_drift,
            "reasons": self.reasons,
        })
    }
}

/// Unix-second field where the API uses `-1` (or absence) for never/unknown.
fn epoch_field(container: &Value, key: &str) -> Option<i64> {
    container
        .get(key)
        .and_then(Value::as_i64)
        .filter(|ts| *ts > 0)
}

fn str_field<'a>(container: &'a Value, key: &str) -> Option<&'a str> {
    container
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// Evaluate scan staleness for one container as of `now_ts` (unix seconds)
/// against a `stale_days` threshold. Returns `None` for inactive containers:
/// deactivation is a deliberate operator act, not a silent scanner failure.
pub fn evaluate(container: &Value, now_ts: i64, stale_days: i64) -> Option<ScanStaleness> {
    let is_active = container
        .get("is_active")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !is_active {
        return None;
    }

    let last_scanned_at = epoch_field(container, "last_scanned_at");
    let last_pushed_at = epoch_field(container, "last_pushed_at");

    let scan_age_days = last_scanned_at.map(|ts| (now_ts - ts) / 86_400);
    let pushed_after_scan = match (last_scanned_at, last_pushed_at) {
        (Some(scanned), Some(pushed)) => pushed > scanned,
        _ => false,
    };
    let tag_drift = match (
        str_field(container, "tag"),
        str_field(container, "last_scanned_tag"),
    ) {
        (Some(tag), Some(scanned_tag)) => tag != scanned_tag,
        _ => false,
    };

    let mut reasons = Vec::new();
    if last_scanned_at.is_none() {
        reasons.push(REASON_NEVER_SCANNED);
    } else if scan_age_days.is_some_and(|age| age > stale_days) {
        reasons.push(REASON_SCAN_OLDER_THAN_LIMIT);
    }
    if pushed_after_scan {
        reasons.push(REASON_PUSHED_AFTER_SCAN);
    }

    Some(ScanStaleness {
        scan_age_days,
        pushed_after_scan,
        tag_drift,
        reasons,
    })
}

/// Filter `containers` down to the stale ones, annotating each with a
/// `scan_staleness` object. Returns `(stale_containers, active_count)`.
pub fn filter_stale(containers: Vec<Value>, now_ts: i64, stale_days: i64) -> (Vec<Value>, usize) {
    let mut active = 0usize;
    let stale = containers
        .into_iter()
        .filter_map(|mut container| {
            let staleness = evaluate(&container, now_ts, stale_days)?;
            active += 1;
            if !staleness.is_stale() {
                return None;
            }
            container["scan_staleness"] = staleness.to_json();
            Some(container)
        })
        .collect();
    (stale, active)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;
    const NOW: i64 = 1_800_000_000;

    fn container(scanned: i64, pushed: i64) -> Value {
        json!({
            "id": 1,
            "name": "registry/app",
            "is_active": true,
            "last_scanned_at": scanned,
            "last_pushed_at": pushed,
            "tag": "",
            "last_scanned_tag": "latest",
        })
    }

    #[test]
    fn fresh_scan_after_push_is_not_stale() {
        let c = container(NOW - DAY, NOW - 2 * DAY);
        let s = evaluate(&c, NOW, 7).unwrap();
        assert!(!s.is_stale());
        assert_eq!(s.scan_age_days, Some(1));
        assert!(!s.pushed_after_scan);
    }

    #[test]
    fn push_after_scan_is_stale_even_when_recent() {
        // Scanned yesterday, pushed today: findings predate the image.
        let c = container(NOW - DAY, NOW - 3600);
        let s = evaluate(&c, NOW, 7).unwrap();
        assert!(s.pushed_after_scan);
        assert_eq!(s.reasons, vec![REASON_PUSHED_AFTER_SCAN]);
    }

    #[test]
    fn old_scan_is_stale_past_the_limit() {
        let c = container(NOW - 10 * DAY, NOW - 20 * DAY);
        let s = evaluate(&c, NOW, 7).unwrap();
        assert_eq!(s.scan_age_days, Some(10));
        assert_eq!(s.reasons, vec![REASON_SCAN_OLDER_THAN_LIMIT]);
    }

    #[test]
    fn stale_days_boundary_is_exclusive() {
        // Exactly N days old is still fresh; N+1 is stale.
        let at_limit = container(NOW - 7 * DAY, NOW - 20 * DAY);
        assert!(!evaluate(&at_limit, NOW, 7).unwrap().is_stale());
        let past_limit = container(NOW - 8 * DAY, NOW - 20 * DAY);
        assert!(evaluate(&past_limit, NOW, 7).unwrap().is_stale());
    }

    #[test]
    fn never_scanned_is_stale_with_null_age() {
        // -1 is the API's "no scan happened yet".
        let c = container(-1, NOW - DAY);
        let s = evaluate(&c, NOW, 7).unwrap();
        assert_eq!(s.scan_age_days, None);
        assert_eq!(s.reasons, vec![REASON_NEVER_SCANNED]);
    }

    #[test]
    fn missing_timestamps_behave_like_never_and_unknown() {
        let c = json!({ "id": 1, "is_active": true });
        let s = evaluate(&c, NOW, 7).unwrap();
        assert_eq!(s.reasons, vec![REASON_NEVER_SCANNED]);
        assert!(!s.pushed_after_scan, "unknown push time must not accuse");
    }

    #[test]
    fn unknown_push_time_cannot_make_a_fresh_scan_stale() {
        let c = container(NOW - DAY, -1);
        assert!(!evaluate(&c, NOW, 7).unwrap().is_stale());
    }

    #[test]
    fn inactive_containers_are_excluded_not_stale() {
        let mut c = container(-1, -1);
        c["is_active"] = json!(false);
        assert!(evaluate(&c, NOW, 7).is_none());
    }

    #[test]
    fn tag_drift_is_informational_only() {
        // The original clue: tag filter says one thing, last scan used another.
        let mut c = container(NOW - DAY, NOW - 2 * DAY);
        c["tag"] = json!("sha-abc123");
        c["last_scanned_tag"] = json!("latest");
        let s = evaluate(&c, NOW, 7).unwrap();
        assert!(s.tag_drift);
        assert!(!s.is_stale(), "drift alone is a clue, not a verdict");
    }

    #[test]
    fn filter_stale_annotates_and_counts_active() {
        let containers = vec![
            container(NOW - DAY, NOW - 2 * DAY),       // fresh
            container(NOW - 30 * DAY, NOW - 40 * DAY), // stale
            {
                let mut c = container(-1, -1);
                c["is_active"] = json!(false);
                c
            }, // inactive, excluded
        ];
        let (stale, active) = filter_stale(containers, NOW, 7);
        assert_eq!(active, 2);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0]["scan_staleness"]["scan_age_days"], 30);
        assert_eq!(
            stale[0]["scan_staleness"]["reasons"][0],
            REASON_SCAN_OLDER_THAN_LIMIT
        );
    }
}
