//! `aikido repos` — list, trigger scans, export licenses.

use aikido_core::api;
use aikido_core::error::ApiError;
use serde_json::Value;

use crate::output::{render_ok, str_val, Column, GlobalFlags, Response};

use super::issues::{mutation_done, render_failure};
use super::require_session;

const LIST_COLUMNS: &[Column] = &[
    Column {
        header: "Name",
        key: "name",
    },
    Column {
        header: "Provider",
        key: "provider",
    },
    Column {
        header: "Branch",
        key: "branch",
    },
    Column {
        header: "Last Scan",
        key: "last_scan_at",
    },
];

pub const LICENSE_COLUMNS: &[Column] = &[
    Column {
        header: "Package",
        key: "name",
    },
    Column {
        header: "License",
        key: "license",
    },
    Column {
        header: "Version",
        key: "version",
    },
];

pub async fn list(
    flags: &GlobalFlags,
    limit: usize,
    name: Option<String>,
    inactive: bool,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let repos = api::list_code_repos(&session.client, limit, name.as_deref(), inactive).await?;

    let count = repos.len();
    let resp = Response::new(Value::Array(repos))
        .with_summary(format!("{count} repositories"))
        .with_count(count);
    render_ok(&flags.format(), resp, LIST_COLUMNS, Some(&format_repo_line)).map_err(render_failure)
}

pub async fn scan(
    flags: &GlobalFlags,
    repo_id: u64,
    sast: bool,
    iac: bool,
    secrets: bool,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    api::scan_repo(&session.client, repo_id, sast, iac, secrets).await?;
    mutation_done(flags, format!("Scan initiated for repository {repo_id}."))
}

pub async fn licenses(flags: &GlobalFlags, repo_id: u64) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let packages = api::repo_licenses(&session.client, repo_id).await?;
    render_licenses(flags, packages)
}

pub fn render_licenses(flags: &GlobalFlags, packages: Vec<Value>) -> Result<(), ApiError> {
    let count = packages.len();
    let resp = Response::new(Value::Array(packages))
        .with_summary(format!("{count} packages"))
        .with_count(count);
    render_ok(
        &flags.format(),
        resp,
        LICENSE_COLUMNS,
        Some(&format_license_line),
    )
    .map_err(render_failure)
}

fn format_repo_line(item: &Value) -> String {
    format!(
        "  {:<30}  {:<12}  {:<20}  {}",
        str_val(item, "name"),
        str_val(item, "provider"),
        str_val(item, "branch"),
        format_last_scan(item.get("last_scan_at")),
    )
}

pub fn format_license_line(item: &Value) -> String {
    format!(
        "  {:<40}  {:<20}  {}",
        str_val(item, "name"),
        str_val(item, "license"),
        str_val(item, "version"),
    )
}

/// `last_scan_at` arrives as a unix timestamp or a date string; render as
/// yyyy-mm-dd in local time (see `output::local_date_from_epoch`).
fn format_last_scan(value: Option<&Value>) -> String {
    match value {
        Some(Value::Number(n)) => n
            .as_i64()
            .and_then(crate::output::local_date_from_epoch)
            .unwrap_or_default(),
        Some(Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|t| {
                t.with_timezone(&chrono::Local)
                    .format("%Y-%m-%d")
                    .to_string()
            })
            .unwrap_or_else(|_| s.clone()),
        _ => String::new(),
    }
}
