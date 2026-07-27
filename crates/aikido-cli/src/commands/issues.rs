//! `aikido issues` — list, show, ignore, snooze, adjust severity.

use aikido_core::api::{self, IssueFilters};
use aikido_core::error::ApiError;
use aikido_core::until;
use serde_json::Value;

use crate::output::{
    detail_lines, render_ok, severity_badge, str_val, Column, Format, GlobalFlags, Response,
};

use super::require_session;

const LIST_COLUMNS: &[Column] = &[
    Column { header: "Severity", key: "severity" },
    Column { header: "CVE", key: "cve_id" },
    Column { header: "Package", key: "affected_package" },
    Column { header: "Repo", key: "code_repo_name" },
    Column { header: "Status", key: "status" },
];

pub async fn list(
    flags: &GlobalFlags,
    severity: Option<String>,
    status: Option<String>,
    limit: usize,
    repo: Option<String>,
    container: Option<String>,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let filters = IssueFilters {
        severity,
        status,
        code_repo_name: repo,
        container_repo_name: container,
    };
    let issues = api::list_issues(&session.client, &filters, Some(limit)).await?;

    let count = issues.len();
    let resp = Response::new(Value::Array(issues))
        .with_summary(format!("{count} issues"))
        .with_count(count);
    render_ok(&flags.format(), resp, LIST_COLUMNS, Some(&format_issue_line))
        .map_err(render_failure)
}

pub async fn show(flags: &GlobalFlags, group_id: u64) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let group = api::get_issue_group(&session.client, group_id).await?;
    let resp = Response::new(group);
    render_ok(&flags.format(), resp, &[], Some(&format_issue_detail)).map_err(render_failure)
}

pub async fn ignore(
    flags: &GlobalFlags,
    issue_id: u64,
    reason: Option<String>,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    api::ignore_issue(&session.client, issue_id, reason.as_deref()).await?;
    mutation_done(flags, format!("Issue {issue_id} ignored."))
}

pub async fn snooze(
    flags: &GlobalFlags,
    issue_id: u64,
    until: &str,
    reason: Option<String>,
) -> Result<(), ApiError> {
    let (snooze_until, date) = until::parse_days(until).map_err(|msg| ApiError::Api {
        status: 400,
        message: format!("invalid --until value {until:?}: {msg}"),
    })?;
    let session = require_session(flags)?;
    api::snooze_issue(&session.client, issue_id, snooze_until, reason.as_deref()).await?;
    mutation_done(flags, format!("Issue {issue_id} snoozed until {date}."))
}

pub async fn severity(
    flags: &GlobalFlags,
    issue_id: u64,
    level: &str,
    reason: &str,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    api::adjust_severity(&session.client, issue_id, level, reason).await?;
    mutation_done(flags, format!("Issue {issue_id} severity adjusted to {level}."))
}

/// Mutation success: a summary-only envelope on stdout in machine formats,
/// a human line on stderr for the TTY.
pub fn mutation_done(flags: &GlobalFlags, summary: String) -> Result<(), ApiError> {
    match flags.format() {
        Format::Styled => {
            eprintln!("{summary}");
            Ok(())
        }
        format => render_ok(&format, Response::summary_only(summary), &[], None)
            .map_err(render_failure),
    }
}

pub fn render_failure(err: anyhow::Error) -> ApiError {
    ApiError::Api {
        status: 0,
        message: format!("rendering output: {err:#}"),
    }
}

fn format_issue_line(item: &Value) -> String {
    let severity = str_val(item, "severity");
    let mut title = str_val(item, "cve_id");
    if title.is_empty() {
        title = str_val(item, "rule");
    }
    let package = str_val(item, "affected_package");
    if !package.is_empty() {
        title = if title.is_empty() {
            package
        } else {
            format!("{title} ({package})")
        };
    }
    let mut repo = str_val(item, "code_repo_name");
    if repo.is_empty() {
        repo = str_val(item, "container_repo_name");
    }
    let status = str_val(item, "status");
    format!(
        "{}  {:<55}  {:<20}  {}",
        severity_badge(&severity),
        title,
        repo,
        status
    )
}

fn format_issue_detail(item: &Value) -> String {
    let cves = item
        .get("related_cve_ids")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(crate::output::cell_text)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();

    let mut pairs = vec![
        ("Title", str_val(item, "title")),
        (
            "Severity",
            format!(
                "{} ({})",
                severity_badge(&str_val(item, "severity")),
                str_val(item, "severity_score")
            ),
        ),
        ("Status", str_val(item, "group_status")),
        ("Fix time", format!("~{} min", str_val(item, "time_to_fix_minutes"))),
        ("Description", str_val(item, "description")),
        ("How to fix", str_val(item, "how_to_fix")),
        ("CVEs", cves),
    ];

    if let Some(locations) = item.get("locations").and_then(Value::as_array) {
        for (i, loc) in locations.iter().enumerate() {
            let name = str_val(loc, "name");
            let loc_type = str_val(loc, "type");
            let text = if loc_type.is_empty() {
                name
            } else {
                format!("{name} ({loc_type})")
            };
            pairs.push((if i == 0 { "Locations" } else { "" }, text));
        }
    }

    detail_lines(&pairs)
}
