//! `aikido containers` — list, show, scan, export licenses, and surface
//! scan freshness. A container whose scanner silently stops reports a low
//! finding count, which reads as healthy — so freshness is shown in the
//! default listing and `--stale-days` makes the staleness check explicit.

use aikido_core::api;
use aikido_core::error::ApiError;
use aikido_core::staleness;
use serde_json::Value;

use crate::output::{detail_lines, render_ok, str_val, Column, GlobalFlags, Response};

use super::issues::{mutation_done, render_failure};
use super::require_session;

const LIST_COLUMNS: &[Column] = &[
    Column {
        header: "Name",
        key: "name",
    },
    Column {
        header: "Tag",
        key: "tag",
    },
    Column {
        header: "Provider",
        key: "provider",
    },
    Column {
        header: "Status",
        key: "status",
    },
    Column {
        header: "Scanned",
        key: "scanned_date",
    },
    Column {
        header: "Pushed",
        key: "pushed_date",
    },
];

pub async fn list(
    flags: &GlobalFlags,
    limit: usize,
    name: Option<String>,
    tag: Option<String>,
    stale_days: Option<i64>,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let containers =
        api::list_containers(&session.client, limit, name.as_deref(), tag.as_deref()).await?;

    let (containers, summary) = match stale_days {
        Some(days) => {
            let now_ts = chrono::Utc::now().timestamp();
            let (stale, active) = staleness::filter_stale(containers, now_ts, days);
            let summary = format!(
                "{} of {} active containers scan-stale (older than {} days, never scanned, or pushed after scan)",
                stale.len(),
                active,
                days
            );
            (stale, summary)
        }
        None => {
            let count = containers.len();
            (containers, format!("{count} containers"))
        }
    };

    // Human-readable scan/push dates for table and styled output; harmless
    // extra fields in --json, where the raw epoch fields remain untouched.
    let containers: Vec<Value> = containers
        .into_iter()
        .map(|mut container| {
            container["scanned_date"] = Value::String(epoch_date(&container, "last_scanned_at"));
            container["pushed_date"] = Value::String(epoch_date(&container, "last_pushed_at"));
            container
        })
        .collect();

    let count = containers.len();
    let resp = Response::new(Value::Array(containers))
        .with_summary(summary)
        .with_count(count);
    render_ok(
        &flags.format(),
        resp,
        LIST_COLUMNS,
        Some(&format_container_line),
    )
    .map_err(render_failure)
}

pub async fn show(flags: &GlobalFlags, container_id: u64) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let container = api::get_container(&session.client, container_id).await?;
    render_ok(
        &flags.format(),
        Response::new(container),
        &[],
        Some(&format_container_detail),
    )
    .map_err(render_failure)
}

pub async fn scan(flags: &GlobalFlags, container_id: u64) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    api::scan_container(&session.client, container_id).await?;
    mutation_done(
        flags,
        format!("Scan queued for container {container_id} (runs asynchronously; check `containers show {container_id}` for last_scanned_at)."),
    )
}

pub async fn licenses(flags: &GlobalFlags, container_id: u64) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let packages = api::container_licenses(&session.client, container_id).await?;
    super::repos::render_licenses(flags, packages)
}

/// Unix-second field rendered as yyyy-mm-dd; the API uses -1 for
/// never/unknown.
fn epoch_date(item: &Value, key: &str) -> String {
    item.get(key)
        .and_then(Value::as_i64)
        .filter(|ts| *ts > 0)
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "never".to_string())
}

fn format_container_line(item: &Value) -> String {
    let name = str_val(item, "name");
    let tag = str_val(item, "tag");
    let name_tag = if tag.is_empty() {
        name
    } else {
        format!("{name}:{tag}")
    };
    let stale_marker = if item.get("scan_staleness").is_some() {
        "  STALE"
    } else {
        ""
    };
    format!(
        "  {:<40}  {:<12}  scanned {:<10}  pushed {:<10}{}",
        name_tag,
        str_val(item, "provider"),
        str_val(item, "scanned_date"),
        str_val(item, "pushed_date"),
        stale_marker,
    )
}

fn format_container_detail(item: &Value) -> String {
    detail_lines(&[
        ("Name", str_val(item, "name")),
        ("Provider", str_val(item, "provider")),
        ("Environment", str_val(item, "environment")),
        ("External ID", str_val(item, "external_id")),
        ("Last scanned", epoch_date(item, "last_scanned_at")),
        ("Last pushed", epoch_date(item, "last_pushed_at")),
        ("Scanned tag", str_val(item, "last_scanned_tag")),
    ])
}
