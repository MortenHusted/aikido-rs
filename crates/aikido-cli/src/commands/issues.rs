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
    Column {
        header: "Severity",
        key: "severity",
    },
    Column {
        header: "CVE",
        key: "cve_id",
    },
    Column {
        header: "Package",
        key: "affected_package",
    },
    Column {
        header: "Repo",
        key: "code_repo_name",
    },
    Column {
        header: "Status",
        key: "status",
    },
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
        issue_group_id: None,
    };
    let issues = api::list_issues(&session.client, &filters, Some(limit)).await?;

    let count = issues.len();
    let resp = Response::new(Value::Array(issues))
        .with_summary(format!("{count} issues"))
        .with_count(count);
    render_ok(
        &flags.format(),
        resp,
        LIST_COLUMNS,
        Some(&format_issue_line),
    )
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
    mutation_done(
        flags,
        format!("Issue {issue_id} severity adjusted to {level}."),
    )
}

/// `issues counts` — severity counts on both axes. The whole point of this
/// command is that "issue groups" (the Aikido dashboard's "Open Issues"
/// unit) and "individual issues" (the rows `issues list` returns) are
/// different units that people conflate, so every output format names the
/// axis in words.
pub async fn counts(
    flags: &GlobalFlags,
    filters: &aikido_core::api::CountFilters,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let counts = api::issue_counts(&session.client, filters).await?;

    let groups_all = axis_count(&counts, "issue_groups");
    let issues_all = axis_count(&counts, "issues");
    let summary = format!(
        "{groups_all} open issue groups (the dashboard's \"Open Issues\" unit) \
         spanning {issues_all} individual issues (the rows `issues list` returns)"
    );

    match flags.format() {
        Format::Markdown => {
            println!("| Unit | All | Critical | High | Medium | Low |");
            println!("|---|---|---|---|---|---|");
            println!(
                "{}",
                counts_row(
                    &counts,
                    "issue_groups",
                    "Issue groups — the Aikido dashboard's \"Open Issues\" number"
                )
            );
            println!(
                "{}",
                counts_row(
                    &counts,
                    "issues",
                    "Individual issues — the rows `issues list` / `/issues/export` return"
                )
            );
            println!("\n{summary}");
            Ok(())
        }
        Format::Styled => {
            println!(
                "{}",
                styled_axis(
                    &counts,
                    "issue_groups",
                    "Issue groups (dashboard \"Open Issues\" unit)"
                )
            );
            println!(
                "{}",
                styled_axis(
                    &counts,
                    "issues",
                    "Individual issues (issues list rows)      "
                )
            );
            println!("\x1b[2m{summary}\x1b[0m");
            Ok(())
        }
        format => render_ok(
            &format,
            Response::new(counts).with_summary(summary),
            &[],
            None,
        )
        .map_err(render_failure),
    }
}

fn axis_count(counts: &Value, axis: &str) -> i64 {
    counts[axis]["all"].as_i64().unwrap_or(0)
}

fn severity_cells(counts: &Value, axis: &str) -> [i64; 5] {
    ["all", "critical", "high", "medium", "low"]
        .map(|severity| counts[axis][severity].as_i64().unwrap_or(0))
}

fn counts_row(counts: &Value, axis: &str, label: &str) -> String {
    let [all, critical, high, medium, low] = severity_cells(counts, axis);
    format!("| {label} | {all} | {critical} | {high} | {medium} | {low} |")
}

fn styled_axis(counts: &Value, axis: &str, label: &str) -> String {
    let [all, critical, high, medium, low] = severity_cells(counts, axis);
    format!(
        "{label}  all {all:>5}   critical {critical:>4}   high {high:>4}   medium {medium:>4}   low {low:>4}"
    )
}

// ---------------------------------------------------------------------------
// Issue groups — the dashboard's unit. A group is keyed by the
// vulnerability and its locations span repos, containers, and clouds, so
// every group mutation here (1) shows the blast radius before acting and
// (2) asserts the API's reported per-issue count against it afterwards.
// A mismatch is an error, not a warning.
// ---------------------------------------------------------------------------

const GROUP_LIST_COLUMNS: &[Column] = &[
    Column {
        header: "ID",
        key: "id",
    },
    Column {
        header: "Severity",
        key: "severity",
    },
    Column {
        header: "Title",
        key: "title",
    },
    Column {
        header: "Status",
        key: "group_status",
    },
];

pub async fn groups_list(
    flags: &GlobalFlags,
    filters: &api::GroupFilters,
    limit: usize,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let groups = api::list_open_issue_groups(&session.client, filters, limit).await?;

    let count = groups.len();
    let scope_note = if filters.code_repo_id.is_some()
        || filters.external_code_repo_id.is_some()
        || filters.code_repo_name.is_some()
        || filters.container_repo_id.is_some()
    {
        " touching the filtered location (groups may also span other repos, containers, and clouds)"
    } else {
        ""
    };
    let resp = Response::new(Value::Array(groups))
        .with_summary(format!("{count} issue groups{scope_note}"))
        .with_count(count);
    render_ok(
        &flags.format(),
        resp,
        GROUP_LIST_COLUMNS,
        Some(&format_group_line),
    )
    .map_err(render_failure)
}

fn format_group_line(item: &Value) -> String {
    let locations = item
        .get("locations")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    format!(
        "{}  {:>10}  {:<55}  {:<10}  {} locations",
        severity_badge(&str_val(item, "severity")),
        str_val(item, "id"),
        str_val(item, "title"),
        str_val(item, "group_status"),
        locations,
    )
}

/// Show what a group mutation is about to touch. Styled mode prints it to
/// stderr *before* acting; machine formats carry the same facts in the
/// final envelope.
fn announce_blast_radius(flags: &GlobalFlags, group_id: u64, blast: &api::GroupBlastRadius) {
    if flags.format() != Format::Styled {
        return;
    }
    eprintln!(
        "Group {group_id}: this acts on the vulnerability across ALL its locations, \
         not just one repo:"
    );
    for location in &blast.locations {
        eprintln!(
            "  - {} ({})",
            str_val(location, "name"),
            str_val(location, "type")
        );
    }
    eprintln!(
        "Open issues expected to be affected: {}",
        blast.expected_issues
    );
}

/// Wrap up a group mutation: assert the API's reported per-issue count
/// against the preflight expectation (when the API reports one), then
/// render locations + counts so the blast radius is on the record.
fn finish_group_mutation(
    flags: &GlobalFlags,
    group_id: u64,
    blast: api::GroupBlastRadius,
    affected: Option<u64>,
    verb: &str,
) -> Result<(), ApiError> {
    if let Some(actual) = affected {
        if actual as usize != blast.expected_issues {
            return Err(ApiError::Api {
                status: 0,
                message: format!(
                    "group {group_id} {verb} affected {actual} issues but {expected} open issues \
                     were expected at preflight. THE MUTATION WAS APPLIED — the group changed \
                     between preflight and mutation; verify it in the Aikido dashboard",
                    expected = blast.expected_issues,
                ),
            });
        }
    }

    let locations = blast.locations.len();
    let summary = match affected {
        Some(actual) => {
            format!("Group {group_id} {verb}: {actual} issues across {locations} locations.")
        }
        None => format!(
            "Group {group_id} {verb} across {locations} locations (~{} open issues; the API \
             reports no per-issue count for this operation).",
            blast.expected_issues
        ),
    };

    match flags.format() {
        Format::Styled => {
            eprintln!("{summary}");
            Ok(())
        }
        format => {
            let data = serde_json::json!({
                "group_id": group_id,
                "locations": blast.locations,
                "expected_issues": blast.expected_issues,
                "affected_issues": affected,
            });
            render_ok(
                &format,
                Response::new(data).with_summary(summary),
                &[],
                None,
            )
            .map_err(render_failure)
        }
    }
}

pub async fn groups_ignore(
    flags: &GlobalFlags,
    group_id: u64,
    reason: Option<String>,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let blast = api::group_blast_radius(&session.client, group_id).await?;
    announce_blast_radius(flags, group_id, &blast);
    let affected = api::ignore_issue_group(&session.client, group_id, reason.as_deref()).await?;
    finish_group_mutation(flags, group_id, blast, affected, "ignored")
}

pub async fn groups_snooze(
    flags: &GlobalFlags,
    group_id: u64,
    until: &str,
    reason: Option<String>,
) -> Result<(), ApiError> {
    let (snooze_until, date) = until::parse_days(until).map_err(|msg| ApiError::Api {
        status: 400,
        message: format!("invalid --until value {until:?}: {msg}"),
    })?;
    let session = require_session(flags)?;
    let blast = api::group_blast_radius(&session.client, group_id).await?;
    announce_blast_radius(flags, group_id, &blast);
    let affected =
        api::snooze_issue_group(&session.client, group_id, snooze_until, reason.as_deref()).await?;
    finish_group_mutation(
        flags,
        group_id,
        blast,
        affected,
        &format!("snoozed until {date}"),
    )
}

pub async fn groups_severity(
    flags: &GlobalFlags,
    group_id: u64,
    level: &str,
    reason: &str,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    let blast = api::group_blast_radius(&session.client, group_id).await?;
    announce_blast_radius(flags, group_id, &blast);
    api::adjust_group_severity(&session.client, group_id, level, reason).await?;
    finish_group_mutation(
        flags,
        group_id,
        blast,
        None,
        &format!("severity adjusted to {level}"),
    )
}

pub async fn groups_unignore(
    flags: &GlobalFlags,
    group_id: u64,
    reason: Option<String>,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    api::unignore_issue_group(&session.client, group_id, reason.as_deref()).await?;
    mutation_done(flags, format!("Group {group_id} unignored."))
}

pub async fn groups_unsnooze(flags: &GlobalFlags, group_id: u64) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    api::unsnooze_issue_group(&session.client, group_id).await?;
    mutation_done(flags, format!("Group {group_id} unsnoozed."))
}

pub async fn unignore(
    flags: &GlobalFlags,
    issue_id: u64,
    reason: Option<String>,
    all_tags: bool,
) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    api::unignore_issue(&session.client, issue_id, reason.as_deref(), all_tags).await?;
    mutation_done(flags, format!("Issue {issue_id} unignored."))
}

pub async fn unsnooze(flags: &GlobalFlags, issue_id: u64, all_tags: bool) -> Result<(), ApiError> {
    let session = require_session(flags)?;
    api::unsnooze_issue(&session.client, issue_id, all_tags).await?;
    mutation_done(flags, format!("Issue {issue_id} unsnoozed."))
}

/// Mutation success: a summary-only envelope on stdout in machine formats,
/// a human line on stderr for the TTY.
pub fn mutation_done(flags: &GlobalFlags, summary: String) -> Result<(), ApiError> {
    match flags.format() {
        Format::Styled => {
            eprintln!("{summary}");
            Ok(())
        }
        format => {
            render_ok(&format, Response::summary_only(summary), &[], None).map_err(render_failure)
        }
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
        (
            "Fix time",
            format!("~{} min", str_val(item, "time_to_fix_minutes")),
        ),
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
