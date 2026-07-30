//! Typed operations over the Aikido public API, shared verbatim by the CLI
//! and the MCP server. All responses are passed through as `serde_json::Value`
//! — the CLI's `--json` contract exposes the raw API objects.

use serde_json::{json, Value};

use crate::client::Client;
use crate::error::ApiError;

/// Filters for `GET /issues/export`. Severity is passed through verbatim as
/// a comma-separated list (`filter_severities`).
#[derive(Debug, Clone, Default)]
pub struct IssueFilters {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub code_repo_name: Option<String>,
    pub container_repo_name: Option<String>,
    pub issue_group_id: Option<u64>,
}

/// `GET /issues/export`, truncated client-side to `limit` when given.
pub async fn list_issues(
    client: &Client,
    filters: &IssueFilters,
    limit: Option<usize>,
) -> Result<Vec<Value>, ApiError> {
    let mut query: Vec<(&str, String)> = Vec::new();
    if let Some(severity) = &filters.severity {
        query.push(("filter_severities", severity.clone()));
    }
    if let Some(status) = &filters.status {
        query.push(("filter_status", status.clone()));
    }
    if let Some(repo) = &filters.code_repo_name {
        query.push(("filter_code_repo_name", repo.clone()));
    }
    if let Some(container) = &filters.container_repo_name {
        query.push(("filter_container_repo_name", container.clone()));
    }
    if let Some(group_id) = filters.issue_group_id {
        query.push(("filter_issue_group_id", group_id.to_string()));
    }

    let raw = client.get("/issues/export", &query).await?;
    let mut issues = expect_array(raw, "/issues/export")?;
    if let Some(limit) = limit {
        issues.truncate(limit);
    }
    Ok(issues)
}

/// Filters for `GET /issues/counts` — every filter the spec documents.
#[derive(Debug, Clone, Default)]
pub struct CountFilters {
    pub code_repo_id: Option<u64>,
    pub external_code_repo_id: Option<String>,
    pub code_repo_name: Option<String>,
    pub container_repo_id: Option<u64>,
    pub team_id: Option<u64>,
    /// Unix seconds; only issues created after this are counted.
    pub since_timestamp: Option<i64>,
}

/// `GET /issues/counts` — severity-bucketed counts on BOTH axes:
/// `issue_groups` (the unit behind the Aikido dashboard's "Open Issues"
/// figure) and `issues` (individual findings, the rows `/issues/export`
/// returns). Same data, different units — callers must never compare one
/// axis to the other.
pub async fn issue_counts(client: &Client, filters: &CountFilters) -> Result<Value, ApiError> {
    let mut query: Vec<(&str, String)> = Vec::new();
    if let Some(id) = filters.code_repo_id {
        query.push(("filter_code_repo_id", id.to_string()));
    }
    if let Some(id) = &filters.external_code_repo_id {
        query.push(("filter_external_code_repo_id", id.clone()));
    }
    if let Some(name) = &filters.code_repo_name {
        query.push(("filter_code_repo_name", name.clone()));
    }
    if let Some(id) = filters.container_repo_id {
        query.push(("filter_container_repo_id", id.to_string()));
    }
    if let Some(id) = filters.team_id {
        query.push(("filter_team_id", id.to_string()));
    }
    if let Some(ts) = filters.since_timestamp {
        query.push(("since_timestamp", ts.to_string()));
    }
    client.get("/issues/counts", &query).await
}

/// `GET /issues/groups/{group_id}`.
pub async fn get_issue_group(client: &Client, group_id: u64) -> Result<Value, ApiError> {
    client.get(&format!("/issues/groups/{group_id}"), &[]).await
}

/// `PUT /issues/{id}/ignore`.
pub async fn ignore_issue(
    client: &Client,
    issue_id: u64,
    reason: Option<&str>,
) -> Result<(), ApiError> {
    let mut body = json!({});
    if let Some(reason) = reason {
        body["reason"] = json!(reason);
    }
    client
        .put(&format!("/issues/{issue_id}/ignore"), body)
        .await?;
    Ok(())
}

/// `PUT /issues/{id}/snooze`. `snooze_until` is a unix timestamp.
pub async fn snooze_issue(
    client: &Client,
    issue_id: u64,
    snooze_until: i64,
    reason: Option<&str>,
) -> Result<(), ApiError> {
    let mut body = json!({ "snooze_until": snooze_until });
    if let Some(reason) = reason {
        body["reason"] = json!(reason);
    }
    client
        .put(&format!("/issues/{issue_id}/snooze"), body)
        .await?;
    Ok(())
}

/// `POST /issues/{id}/severity/adjust`.
pub async fn adjust_severity(
    client: &Client,
    issue_id: u64,
    level: &str,
    reason: &str,
) -> Result<(), ApiError> {
    client
        .post(
            &format!("/issues/{issue_id}/severity/adjust"),
            json!({ "adjusted_severity": level, "reason": reason }),
        )
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Issue groups
//
// A group is keyed by the vulnerability, not by where it appears: its
// `locations` span code repos, containers, and clouds (the spec documents
// this explicitly, and in practice most groups span several). Group-level
// mutations therefore act workspace-wide — every caller must surface that.
// ---------------------------------------------------------------------------

/// Filters for `GET /open-issue-groups` — every filter the spec documents.
#[derive(Debug, Clone, Default)]
pub struct GroupFilters {
    pub code_repo_id: Option<u64>,
    pub external_code_repo_id: Option<String>,
    pub code_repo_name: Option<String>,
    pub container_repo_id: Option<u64>,
    pub team_id: Option<u64>,
    pub issue_type: Option<String>,
    /// Default is `open` server-side.
    pub status: Option<String>,
}

/// `GET /open-issue-groups` — the listing behind the Aikido dashboard's
/// "Open Issues" number. Note: a location filter (repo/container) returns
/// groups that *touch* that location; the groups themselves may span other
/// repos, containers, and clouds.
pub async fn list_open_issue_groups(
    client: &Client,
    filters: &GroupFilters,
    limit: usize,
) -> Result<Vec<Value>, ApiError> {
    let mut base_query: Vec<(&str, String)> = Vec::new();
    if let Some(id) = filters.code_repo_id {
        base_query.push(("filter_code_repo_id", id.to_string()));
    }
    if let Some(id) = &filters.external_code_repo_id {
        base_query.push(("filter_external_code_repo_id", id.clone()));
    }
    if let Some(name) = &filters.code_repo_name {
        base_query.push(("filter_code_repo_name", name.clone()));
    }
    if let Some(id) = filters.container_repo_id {
        base_query.push(("filter_container_repo_id", id.to_string()));
    }
    if let Some(id) = filters.team_id {
        base_query.push(("filter_team_id", id.to_string()));
    }
    if let Some(issue_type) = &filters.issue_type {
        base_query.push(("filter_issue_type", issue_type.clone()));
    }
    if let Some(status) = &filters.status {
        base_query.push(("filter_status", status.clone()));
    }
    paginate(client, "/open-issue-groups", base_query, limit, 100).await
}

/// What a group-level mutation will touch: its locations and how many open
/// issues it currently contains. Computed *before* mutating so callers can
/// show the blast radius and assert the outcome against it.
#[derive(Debug, Clone)]
pub struct GroupBlastRadius {
    pub locations: Vec<Value>,
    /// Open issues currently in the group.
    pub expected_issues: usize,
}

pub async fn group_blast_radius(
    client: &Client,
    group_id: u64,
) -> Result<GroupBlastRadius, ApiError> {
    let detail = get_issue_group(client, group_id).await?;
    let locations = detail
        .get("locations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let open_issues = list_issues(
        client,
        &IssueFilters {
            status: Some("open".to_string()),
            issue_group_id: Some(group_id),
            ..IssueFilters::default()
        },
        None,
    )
    .await?;
    Ok(GroupBlastRadius {
        locations,
        expected_issues: open_issues.len(),
    })
}

/// Verify the affected count reported by a guarded forward group mutation.
/// A mismatch is detected only after the endpoint has applied the mutation,
/// so the shared error must never read like a no-op failure.
pub fn verify_group_mutation_count(
    group_id: u64,
    blast: &GroupBlastRadius,
    affected: Option<u64>,
    verb: &str,
) -> Result<(), ApiError> {
    if let Some(actual) = affected {
        if actual != blast.expected_issues as u64 {
            return Err(ApiError::GroupMutationMismatch {
                group_id,
                verb: verb.to_string(),
                actual,
                expected: blast.expected_issues,
            });
        }
    }
    Ok(())
}

/// `PUT /issues/groups/{id}/ignore`. Returns the number of single issues
/// the API reports as ignored, when it reports one.
pub async fn ignore_issue_group(
    client: &Client,
    group_id: u64,
    reason: Option<&str>,
) -> Result<Option<u64>, ApiError> {
    let mut body = json!({});
    if let Some(reason) = reason {
        body["reason"] = json!(reason);
    }
    let response = client
        .put(&format!("/issues/groups/{group_id}/ignore"), body)
        .await?;
    Ok(response
        .get("ignored_single_issues_amount")
        .and_then(Value::as_u64))
}

/// `PUT /issues/groups/{id}/snooze`. Returns the number of single issues
/// the API reports as snoozed, when it reports one.
pub async fn snooze_issue_group(
    client: &Client,
    group_id: u64,
    snooze_until: i64,
    reason: Option<&str>,
) -> Result<Option<u64>, ApiError> {
    let mut body = json!({ "snooze_until": snooze_until });
    if let Some(reason) = reason {
        body["reason"] = json!(reason);
    }
    let response = client
        .put(&format!("/issues/groups/{group_id}/snooze"), body)
        .await?;
    Ok(response
        .get("snoozed_single_issues_amount")
        .and_then(Value::as_u64))
}

/// `POST /issues/groups/{id}/severity/adjust`. The API reports no
/// per-issue count for this one.
pub async fn adjust_group_severity(
    client: &Client,
    group_id: u64,
    level: &str,
    reason: &str,
) -> Result<(), ApiError> {
    client
        .post(
            &format!("/issues/groups/{group_id}/severity/adjust"),
            json!({ "adjusted_severity": level, "reason": reason }),
        )
        .await?;
    Ok(())
}

/// `PUT /issues/groups/{id}/unignore`.
pub async fn unignore_issue_group(
    client: &Client,
    group_id: u64,
    reason: Option<&str>,
) -> Result<(), ApiError> {
    let mut body = json!({});
    if let Some(reason) = reason {
        body["reason"] = json!(reason);
    }
    client
        .put(&format!("/issues/groups/{group_id}/unignore"), body)
        .await?;
    Ok(())
}

/// `PUT /issues/groups/{id}/unsnooze` — no body.
pub async fn unsnooze_issue_group(client: &Client, group_id: u64) -> Result<(), ApiError> {
    client
        .put(&format!("/issues/groups/{group_id}/unsnooze"), json!({}))
        .await?;
    Ok(())
}

/// `PUT /issues/{id}/unignore`.
pub async fn unignore_issue(
    client: &Client,
    issue_id: u64,
    reason: Option<&str>,
    apply_for_all_tags: bool,
) -> Result<(), ApiError> {
    let mut body = json!({});
    if let Some(reason) = reason {
        body["reason"] = json!(reason);
    }
    if apply_for_all_tags {
        body["apply_for_all_tags"] = json!(true);
    }
    client
        .put(&format!("/issues/{issue_id}/unignore"), body)
        .await?;
    Ok(())
}

/// `PUT /issues/{id}/unsnooze`.
pub async fn unsnooze_issue(
    client: &Client,
    issue_id: u64,
    apply_for_all_tags: bool,
) -> Result<(), ApiError> {
    let mut body = json!({});
    if apply_for_all_tags {
        body["apply_for_all_tags"] = json!(true);
    }
    client
        .put(&format!("/issues/{issue_id}/unsnooze"), body)
        .await?;
    Ok(())
}

/// `GET /repositories/code`, paginated server-side (per_page ≤ 200) and
/// truncated client-side to `limit`.
pub async fn list_code_repos(
    client: &Client,
    limit: usize,
    name: Option<&str>,
    include_inactive: bool,
) -> Result<Vec<Value>, ApiError> {
    let mut base_query: Vec<(&str, String)> = Vec::new();
    if let Some(name) = name {
        base_query.push(("filter_name", name.to_string()));
    }
    if include_inactive {
        base_query.push(("include_inactive", "true".to_string()));
    }
    paginate(client, "/repositories/code", base_query, limit, 200).await
}

/// `POST /repositories/code/{id}/scan` — expects 204 No Content.
pub async fn scan_repo(
    client: &Client,
    repo_id: u64,
    sast: bool,
    iac: bool,
    secrets: bool,
) -> Result<(), ApiError> {
    let mut query: Vec<(&str, String)> = Vec::new();
    if sast {
        query.push(("include_sast_scan", "true".to_string()));
    }
    if iac {
        query.push(("include_iac_scan", "true".to_string()));
    }
    if secrets {
        query.push(("include_secrets_scan", "true".to_string()));
    }
    client
        .post_no_content(&format!("/repositories/code/{repo_id}/scan"), &query)
        .await
}

/// `GET /repositories/code/{id}/licenses/export`, normalised to a list.
pub async fn repo_licenses(client: &Client, repo_id: u64) -> Result<Vec<Value>, ApiError> {
    let raw = client
        .get(
            &format!("/repositories/code/{repo_id}/licenses/export"),
            &[],
        )
        .await?;
    Ok(normalise_to_list(raw))
}

/// `GET /containers`, paginated server-side (per_page ≤ 20) and truncated
/// client-side to `limit`.
pub async fn list_containers(
    client: &Client,
    limit: usize,
    name: Option<&str>,
    tag: Option<&str>,
) -> Result<Vec<Value>, ApiError> {
    let mut base_query: Vec<(&str, String)> = Vec::new();
    if let Some(name) = name {
        base_query.push(("filter_name", name.to_string()));
    }
    if let Some(tag) = tag {
        base_query.push(("filter_tag", tag.to_string()));
    }
    paginate(client, "/containers", base_query, limit, 20).await
}

/// `POST /containers/{id}/scan` — queue a container scan. Fire-and-forget:
/// a 200 `{"success": 1}` means the scan was *started*; the API returns no
/// job handle to await completion.
pub async fn scan_container(client: &Client, container_id: u64) -> Result<(), ApiError> {
    client
        .post_no_content(&format!("/containers/{container_id}/scan"), &[])
        .await
}

/// `GET /containers/{id}`.
pub async fn get_container(client: &Client, container_id: u64) -> Result<Value, ApiError> {
    client
        .get(&format!("/containers/{container_id}"), &[])
        .await
}

/// `GET /containers/{id}/licenses/export`, normalised to a list.
pub async fn container_licenses(
    client: &Client,
    container_id: u64,
) -> Result<Vec<Value>, ApiError> {
    let raw = client
        .get(&format!("/containers/{container_id}/licenses/export"), &[])
        .await?;
    Ok(normalise_to_list(raw))
}

/// Page through a list endpoint (`page` starts at 0) until `limit` items are
/// collected or the server returns a short page.
async fn paginate(
    client: &Client,
    path: &str,
    base_query: Vec<(&str, String)>,
    limit: usize,
    max_per_page: usize,
) -> Result<Vec<Value>, ApiError> {
    let per_page = limit.clamp(1, max_per_page);
    let mut all: Vec<Value> = Vec::new();
    let mut page = 0usize;

    loop {
        let mut query = base_query.clone();
        query.push(("per_page", per_page.to_string()));
        query.push(("page", page.to_string()));

        let raw = client.get(path, &query).await?;
        let page_items = expect_array(raw, path)?;
        let short_page = page_items.len() < per_page;
        all.extend(page_items);

        if all.len() >= limit || short_page {
            break;
        }
        page += 1;
    }

    all.truncate(limit);
    Ok(all)
}

fn expect_array(value: Value, path: &str) -> Result<Vec<Value>, ApiError> {
    match value {
        Value::Array(items) => Ok(items),
        other => Err(ApiError::Api {
            status: 200,
            message: format!("parse response: {path} returned non-array: {other}"),
        }),
    }
}

/// License exports may return a single object; table rendering wants a list.
fn normalise_to_list(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items,
        other => vec![other],
    }
}
